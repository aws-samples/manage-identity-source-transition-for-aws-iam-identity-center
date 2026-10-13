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
###### IdC User/Group Permission Set Backup
######
###### NOTE: ListAccountAssignmentsForPrincipal (used in an earlier version of
###### this script) does not return literal, direct-only assignments for a
###### USER principal. It returns that user's *effective* access, direct
###### assignments plus anything inherited via group membership, both
###### reported as if they were direct to the user. That produced a
###### "(direct)" duplicate of every group-derived grant in the backup for
###### every user, which is not real AWS state. This version instead walks
###### every permission set's provisioned accounts and reads the literal
###### assignment records via ListAccountAssignments (account + permission
###### set scoped, no principal input, so there is no expansion to resolve).
###############################################################################
def get_permission_set_arns(identity_store_arn):
    try:
        response = sso_admin_client.list_permission_sets(InstanceArn=identity_store_arn)
        results = response['PermissionSets']
    except:
        logger.error("Unable to call ListPermissionSets API call using idc_instance_arn: {}".format(identity_store_arn))
        sys.exit(1)

    while "NextToken" in response:
        response = sso_admin_client.list_permission_sets(
            InstanceArn=identity_store_arn,
            NextToken=response["NextToken"])
        results.extend(response["PermissionSets"])

    return results

def get_accounts_for_permission_set(identity_store_arn, permission_set_arn):
    try:
        response = sso_admin_client.list_accounts_for_provisioned_permission_set(
            InstanceArn=identity_store_arn,
            PermissionSetArn=permission_set_arn)
        results = response['AccountIds']
    except:
        logger.error("Unable to list provisioned accounts for permission set: {}".format(permission_set_arn))
        return []

    while "NextToken" in response:
        response = sso_admin_client.list_accounts_for_provisioned_permission_set(
            InstanceArn=identity_store_arn,
            PermissionSetArn=permission_set_arn,
            NextToken=response["NextToken"])
        results.extend(response["AccountIds"])

    return results

def get_literal_account_assignments(identity_store_arn, account_id, permission_set_arn):
    try:
        response = sso_admin_client.list_account_assignments(
            InstanceArn=identity_store_arn,
            AccountId=account_id,
            PermissionSetArn=permission_set_arn)
        results = response['AccountAssignments']
    except:
        logger.error("Unable to list assignments for account: {} permission set: {}".format(account_id, permission_set_arn))
        return []

    while "NextToken" in response:
        response = sso_admin_client.list_account_assignments(
            InstanceArn=identity_store_arn,
            AccountId=account_id,
            PermissionSetArn=permission_set_arn,
            NextToken=response["NextToken"])
        results.extend(response["AccountAssignments"])

    return results

def backup_account_assignments(identity_store_arn, user_filename, group_filename):
    user_assignments = {}
    group_assignments = {}

    permission_set_arns = get_permission_set_arns(identity_store_arn)
    logger.info("Found {} permission sets".format(len(permission_set_arns)))

    for permission_set_arn in permission_set_arns:
        account_ids = get_accounts_for_permission_set(identity_store_arn, permission_set_arn)
        for account_id in account_ids:
            assignments = get_literal_account_assignments(identity_store_arn, account_id, permission_set_arn)
            for assignment in assignments:
                principal_id = assignment['PrincipalId']
                principal_type = assignment['PrincipalType']
                entry = {permission_set_arn: account_id}

                if principal_type == 'USER':
                    username = users.get(principal_id)
                    if not username:
                        logger.warning(
                            "Skipping assignment for unknown USER principal id: {} (account {}, permission set {}); "
                            "likely an orphaned assignment left behind after the user was deleted".format(
                                principal_id, account_id, permission_set_arn))
                        continue
                    user_assignments.setdefault(username, []).append(entry)
                elif principal_type == 'GROUP':
                    displayname = groups.get(principal_id)
                    if not displayname:
                        logger.warning(
                            "Skipping assignment for unknown GROUP principal id: {} (account {}, permission set {})".format(
                                principal_id, account_id, permission_set_arn))
                        continue
                    group_assignments.setdefault(displayname, []).append(entry)

    for username, assignments in user_assignments.items():
        logger.info("Retrieved {} direct account assignments for USER: {}".format(len(assignments), username))
    for displayname, assignments in group_assignments.items():
        logger.info("Retrieved {} account assignments for GROUP: {}".format(len(assignments), displayname))

    write_to_json_file(user_filename, user_assignments)
    write_to_json_file(group_filename, group_assignments)

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
    backup_account_assignments(idc_instance_arn, args.user_assignments_backup, args.group_assignments_backup)
    backup_app_assignments(idc_instance_arn, args.app_assignments_backup)
