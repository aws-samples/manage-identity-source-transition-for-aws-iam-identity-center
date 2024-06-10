import os
import sys
import logging
import argparse
import boto3
import json
import backoff

# connection setup
sso_admin_client = boto3.client('sso-admin')
identitystore_client = boto3.client('identitystore')

backoff_retry_attempts = 5

###############################################################################
###### Helper functions
###############################################################################
def get_user_name_id_mapping(identity_store_id):
    try: 
        response = identitystore_client.list_users(IdentityStoreId=identity_store_id)
        results = response['Users']
    except: 
        logger.error("Unable to call ListUsers API call using idc-id: {}".format(identity_store_id))
        sys.exit(1)
    
    while "NextToken" in response:
        response = identitystore_client.list_users(
            IdentityStoreId=identity_store_id, 
            NextToken=response["NextToken"])
        results.extend(response["Users"])
        
    return {sub['UserName'].lower():sub['UserId'] for sub in results}

def get_group_name_id_mapping(identity_store_id):
    try: 
        response = identitystore_client.list_groups(IdentityStoreId=identity_store_id)
        results = response['Groups']
    except: 
        logger.error("Unable to call ListGroups API call using idc-id: {}".format(identity_store_id))
        sys.exit(1)
    
    while "NextToken" in response:
        response = identitystore_client.list_groups(
            IdentityStoreId=identity_store_id, 
            NextToken=response["NextToken"])
        results.extend(response["Groups"])
    
    return {sub['DisplayName'].lower():sub['GroupId'] for sub in results}

def get_application_arns(identity_store_arn):
    try: 
        response = sso_admin_client.list_applications(InstanceArn=identity_store_arn)
        results = response['Applications']
    except:
        logger.error("Unable to call ListApplications API call using idc_instance_arn: {}".format(identity_store_arn))
        sys.exit(1)
        
    while "NextToken" in response:
        response = sso_admin_client.list_applications(
            InstanceArn=identity_store_arn,
            NextToken=response["NextToken"]
        )
        results.extend(response["Applications"])
    
    return [sub['ApplicationArn'] for sub in results]

def load_account_assignments(filename):
    try: 
        with open(filename, encoding="utf-8") as f: 
            return json.load(f)[os.path.splitext(filename)[0]]
    except FileNotFoundError: 
        logger.error("Unable to find file: {}".format(filename))
        sys.exit(1)
    except: 
        logger.error("Unable to load file: {}".format(filename))
        sys.exit(1)
    

###############################################################################
###### IdC User Account Assignment Restore
###### Assuming UserName is unique and constant
###############################################################################

# exponential backoff to retrieve account creation results
@backoff.on_predicate(backoff.expo, lambda x: x['Status'] == "IN_PROGRESS", max_tries=backoff_retry_attempts)
def get_principal_account_creation_results(identity_store_arn, requestid): 
    response = sso_admin_client.describe_account_assignment_creation_status(
        AccountAssignmentCreationRequestId=requestid, 
        InstanceArn=identity_store_arn)['AccountAssignmentCreationStatus']
    return response

def create_principal_account_assignment(identity_store_arn, principal_id, principal_type, assignment):
    try: 
        arn, account = list(assignment.items())[0]
        response = sso_admin_client.create_account_assignment(
            InstanceArn=identity_store_arn, 
            PermissionSetArn = arn,
            PrincipalId=principal_id,
            PrincipalType=principal_type,
            TargetId=account,
            TargetType='AWS_ACCOUNT')
    except: 
        logger.error("Unable to call CreateAccountAssignment for {} id: {}".format(principal_type, principal_id))
        return False
    
    results = response['AccountAssignmentCreationStatus']
    status = results['Status']
    if status == "SUCCEEDED":
        return True
    elif status == "IN_PROGRESS": 
        # overwrite account creation results
        results = get_principal_account_creation_results(identity_store_arn, results['RequestId'])
        if results['Status'] == "SUCCEEDED":
            return True
        elif results['Status'] == "IN_PROGRESS": 
            logger.warning("Account assignment in progress for {} id: {} after {} retry attempts".format(principal_type, principal_id, backoff_retry_attempts))
            return False
    
    # status FAILED
    logger.error("Failed to create account assignment for {} id: {}, reason: {}".format(principal_type, principal_id, results['FailureReason']))
    return False

def restore_user_assignments(identity_store_arn, filename):
    user_assignments = load_account_assignments(filename)
    logger.info("Successfully retrieved mapping information for {} users".format(len(user_assignments)))
    
    for username, assignments in user_assignments.items():
        if username.lower() not in users: 
            logger.error("Username: {} does not exist. Unable to assign account".format(username))
            continue
        userid = users[username.lower()]
        failed_assignments = 0
        for assignment in assignments: 
            if not create_principal_account_assignment(identity_store_arn, userid, 'USER', assignment): 
                failed_assignments += 1
        logger.info("Created {} successful, {} failed assignements for user id: {}".format(
            len(assignments)-failed_assignments, failed_assignments, userid))
    return 
    
###############################################################################
###### IdC Group Account Assignment Restore
###### Assuming UserName is unique and constant
###############################################################################

def restore_group_assignments(identity_store_arn, filename):
    group_assignments = load_account_assignments(filename)
    logger.info("Successfully retrieved mapping information for {} groups".format(len(group_assignments)))
    
    for displayname, assignments in group_assignments.items():
        if displayname.lower() not in groups: 
            logger.error("Group displayname: {} does not exist. Unable to assign account".format(displayname))
            continue
        groupid = groups[displayname.lower()]
        failed_assignments = 0
        for assignment in assignments: 
            if not create_principal_account_assignment(identity_store_arn, groupid, 'GROUP', assignment): 
                failed_assignments += 1
        logger.info("Created {} successful, {} failed assignements for group id: {}".format(
            len(assignments)-failed_assignments, failed_assignments, groupid))
    return 

###############################################################################
###### IdC Application Assignment Restore
###### Assuming UserName for Users, DisplayName for Groups are unique and constant
###############################################################################

def create_principal_application_assignment(application_arn, assignment):
    try: 
        principal_type, principal_name = list(assignment.items())[0]
        principal_id = ''
        if principal_type == 'USER':
            if principal_name.lower() not in users:
                logger.error("Username: {} does not exist. Unable to assign application".format(principal_name))
                return False
            principal_id = users[principal_name.lower()]
        elif principal_type == 'GROUP':
            if principal_name.lower() not in groups:
                logger.error("Group displayname: {} does not exist. Unable to assign application".format(principal_name))
                return False
            principal_id = groups[principal_name.lower()]
        else: 
            logger.error("Unknown principal type {}. Unable to assign application".format(principal_type))
            return False
        response = sso_admin_client.create_application_assignment(
            ApplicationArn = application_arn, 
            PrincipalId = principal_id, 
            PrincipalType = principal_type)
        return True
    except: 
        logger.error("Unable to call CreateApplicationAssignment for {} id: {}".format(principal_type, principal_id))
        return False

def restore_app_assignments(filename): 
    app_assignments = load_account_assignments(filename)
    logger.info("Successfully retrieved mapping information for {} apps".format(len(app_assignments)))
    
    for app_arn, assignments in app_assignments.items():
        if app_arn not in apps: 
            logger.error("Application: {} does not exist in current idenity source".format(app_arn))
            continue
        failed_assignments = 0
        for assignment in assignments: 
            if not create_principal_application_assignment(app_arn, assignment): 
                failed_assignments += 1
        logger.info("Created {} successful, {} failed assignements for application: {}".format(
            len(assignments)-failed_assignments, failed_assignments, app_arn))
            

if __name__ == "__main__": 
    # configure input argumented
    parser = argparse.ArgumentParser()
    parser.add_argument("--idc-id", help="identity store id, such as d-1234567890", required=True)
    parser.add_argument("--idc-arn", help="arn of your IAM Identity Center instance", required=True)
    parser.add_argument("--logging", help="logging level", default="INFO", choices={"DEBUG","INFO","WARNING","ERROR"})
    parser.add_argument("--user-assignments-backup", help="Backup file for user assignments, default to UserAssignments.json", default="UserAssignments.json")
    parser.add_argument("--group-assignments-backup", help="Backup file for group assignments, default to GroupAssignments.json", default="GroupAssignments.json")
    parser.add_argument("--app-assignments-backup", help="Backup file for application assignments, default to AppAssignments.json", default="AppAssignments.json")
    args = parser.parse_args()
    
    # configure logging
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.getLevelName(args.logging),
        format='%(asctime)s %(levelname)s %(filename)s:%(lineno)s - %(message)s')
    # only log giveup events for the backoff library
    logging.getLogger('backoff').setLevel(logging.ERROR)
    
    # set static variables
    idc_instance_arn = args.idc_arn
    idc_id = args.idc_id
    
    # retrieve users, groups, and application information
    users = get_user_name_id_mapping(idc_id)
    logger.info("Successfully retrieved information for {} synced users".format(len(users)))
    groups = get_group_name_id_mapping(idc_id)
    logger.info("Successfully retrieved information for {} synced groups".format(len(groups)))
    apps = get_application_arns(idc_instance_arn)
    logger.info("Successfully retrieved information for {} applications".format(len(apps)))
    
    restore_user_assignments(idc_instance_arn, args.user_assignments_backup)
    restore_group_assignments(idc_instance_arn, args.group_assignments_backup)
    restore_app_assignments(args.app_assignments_backup)