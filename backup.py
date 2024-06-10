import os
import sys
import logging
import argparse
import boto3
import json

# connection setup
sso_admin_client = boto3.client('sso-admin')
identitystore_client = boto3.client('identitystore')

###############################################################################
###### Helper functions
###############################################################################
def get_user_id_name_mapping(identity_store_id):
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
        
    return {sub['UserId']:sub['UserName'] for sub in results}

def get_group_id_name_mapping(identity_store_id):
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
    
    return {sub['GroupId']:sub['DisplayName'] for sub in results}

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


def write_to_json_file(filename, content):
    with open(filename, 'w', encoding="utf-8") as f:
        json.dump({os.path.splitext(filename)[0]: content}, f)

###############################################################################
###### IdC User Permission Set Backup
###### Assuming UserName is unique and constant
###############################################################################
def get_principal_account_assignments(identity_store_arn, principal_id, principal_type):
    try: 
        response = sso_admin_client.list_account_assignments_for_principal(
            InstanceArn=identity_store_arn, 
            PrincipalId=principal_id,
            PrincipalType=principal_type)
        results = response['AccountAssignments']
    except: 
        logger.error("Unable to list assignments for {} id: {}".format(principal_type, principal_id))
        return
    
    while "NextToken" in response:
        response = sso_admin_client.list_account_assignments_for_principal(
            InstanceArn=identity_store_arn, 
            PrincipalId=principal_id,
            PrincipalType=principal_type, 
            NextToken=response["NextToken"]
        )
        results.extend(response["AccountAssignments"])
    
    return [ {sub['PermissionSetArn']:sub['AccountId']} for sub in results]

def backup_user_assignments(identity_store_arn, filename):
    user_assignments = {}
    
    for userid, username in users.items():
        assignments = get_principal_account_assignments(identity_store_arn, userid, 'USER')
        if assignments == None: 
            continue
        user_assignments[username] = assignments
        logger.info("Retrieved {} account assignments for USER id: {}".format(len(assignments), userid))
    
    write_to_json_file(filename, user_assignments)
    

###############################################################################
###### IdC Group Permission Set Backup
###### Assuming DisplayName is unique and constant
###############################################################################

def backup_group_assignments(identity_store_arn, filename):
    group_assignments = {}
    
    for groupid, displayname in groups.items():
        assignments = get_principal_account_assignments(identity_store_arn, groupid, 'GROUP')
        if assignments == None: 
            continue
        group_assignments[displayname] = assignments
        logger.info("Retrieved {} account assignments for GROUP id: {}".format(len(assignments), groupid))
    
    write_to_json_file(filename, group_assignments)

###############################################################################
###### IdC Application Assignment  Backup
###### Assuming UserName for Users, DisplayName for Groups are unique and constant
###############################################################################

def get_principal_application_assignments(application_arn): 
    try: 
        response = sso_admin_client.list_application_assignments(
            ApplicationArn=application_arn)
        results = response['ApplicationAssignments']
    except: 
        logger.error("Unable to list assignments for application: {}".format(application_arn))
        return
    
    while "NextToken" in response:
        response = sso_admin_client.list_application_assignments(
            ApplicationArn=application_arn, 
            NextToken=response["NextToken"]
        )
        results.extend(response["ApplicationAssignments"])
    
    # swap PrincipalId to Name
    assignments = []
    for result in results:
        if result['PrincipalType'] == 'USER':
            assignments.append({'USER': users[result['PrincipalId']]})
        elif result['PrincipalType'] == 'GROUP':
            assignments.append({'GROUP': groups[result['PrincipalId']]})
        else:
            pass
        
    return assignments

def backup_app_assignments(identity_store_arn, filename):
    application_arns = get_application_arns(identity_store_arn)
    app_assignments = {}
    
    for arn in application_arns: 
        assignments = get_principal_application_assignments(arn)
        if assignments == None: 
            continue
        app_assignments[arn] = assignments
        logger.info("Retrieved {} application assignments for application: {}".format(len(assignments), arn))
    
    write_to_json_file(filename, app_assignments)
    

###############################################################################
###### Main Execution
###############################################################################

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
    
    # set static variables
    idc_instance_arn = args.idc_arn
    idc_id = args.idc_id
    
    # retrieve users, groups, and application information
    users = get_user_id_name_mapping(idc_id)
    logger.info("Successfully retrieved information for {} users".format(len(users)))
    groups = get_group_id_name_mapping(idc_id)
    logger.info("Successfully retrieved information for {} groups".format(len(groups)))
    apps = get_application_arns(idc_instance_arn)
    logger.info("Successfully retrieved information for {} applications".format(len(apps)))
    
    # backing up mappings for users and groups
    backup_user_assignments(idc_instance_arn, args.user_assignments_backup)
    backup_group_assignments(idc_instance_arn, args.group_assignments_backup)
    backup_app_assignments(idc_instance_arn, args.app_assignments_backup)
