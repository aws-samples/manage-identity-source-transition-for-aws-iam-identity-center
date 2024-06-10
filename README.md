## Manage identity source transition for AWS IAM Identity Center

This repository provides sample code ([backup.py](backup.py) and [restore.py](restore.py)) to help you backup and restore assignments for [AWS accounts](https://docs.aws.amazon.com/singlesignon/latest/userguide/manage-your-accounts.html) and [applications](https://docs.aws.amazon.com/singlesignon/latest/userguide/manage-your-applications.html) within [AWS IAM Identity Center](https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html).

Transition scope limits to [identity source](https://docs.aws.amazon.com/singlesignon/latest/userguide/manage-your-identity-source.html) configuration. This means [permission sets](https://docs.aws.amazon.com/singlesignon/latest/userguide/permissionsetsconcept.html) and applications configured with IAM Identity Centre will not change.

If your application integration uses a separate identity source and requires importing users or groups from AWS IAM Identity Center, using the [CreateApplicationAssignments](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_CreateApplicationAssignment.html) API to restore application assignments will **NOT** preserve end-user access.

### Prerequisites
Both scripts are tested on [AWS Cloud9](https://aws.amazon.com/cloud9/) instance, using [AWS SDK for Python (Boto3)](https://aws.amazon.com/sdk-for-python/) to interact with IAM Identity Center. 

1. Follow the [AWS documentation](https://docs.aws.amazon.com/cloud9/latest/user-guide/create-environment-ssh.html) to create an AWS Cloud9 environment in the same account and region where you setup your IAM Identity Center.
2. Clone the sample scripts from GitHub.
```
git clone <LINK>
cd <Repo>
```
3. Install the required libraries
```
pip3 install boto3
pip3 install backoff
```
4. Setup environment variables. 
- Replace `<IDC-INSTANCE-ARN>` with your IAM Identity Center instance ARN, format "arn:aws:sso:::instance/ssoins-instanceId"
- Replace `<IDC-STORE-ID>` with your identity store id for your identity source, format "d-1234567890"
- Replace `<REGION>` with your current region
```
export IDC_ARN=<IDC-INSTANCE-ARN>
export IDC_ID=<IDC-STORE-ID>
export AWS_DEFAULT_REGION=<REGION>
```

After you modify the identity source, the identity store id will change. Please re-export the value of `IDC_ID` by replacing `<NEW-IDC-STORE-ID>` with you new identity store id.
```
export IDC_ID=<NEW-IDC-STORE-ID>
```

### Executing the backup and restore scripts

The backup.py script should be ran prior to switching your identity source. 

This restore.py script should be ran after you change to the target identity source, and have synced over your users and groups.

Both scirpts base the assignment association with unique `UserName` attribute for users, and `DisplayName` attribute for groups. 

#### Running the backup.py

You can run the following command to backup your users, groups and applications assignments.
```
python3 backup.py --idc-id $IDC_ID --idc-arn $IDC_ARN
```

This script will output by default three json files containing backup information `UserAssignments.json`, `GroupAssignments.json`, `AppAssignments.json`. To change the name of the files, or change the logging level, you can use the following command to retrieve the other supported parameters.
```
python3 backup.py -h
```

Permissions required for running this backup script as following. The resource section is not constrained because all users, groups, and applications information are required.
``` json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Statement0",
            "Effect": "Allow",
            "Action": [
                "sso:ListAccountAssignmentsForPrincipal",
                "sso:ListApplications",
                "sso:ListApplicationAssignments",
                "identitystore:ListUsers",
                "identitystore:ListGroups"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```


#### Running the restore.py script

You can run the following command to restore your users, groups and applications assignments. Ensure that you have updated `IDC_ID` with your new identity store id. 
```
python3 restore.py --idc-id $IDC_ID --idc-arn $IDC_ARN
```

This script will leverage the three backup files outputed from backup.py. By default, it will try to look for `UserAssignments.json`, `GroupAssignments.json`, `AppAssignments.json`. To use different filenames, or change the logging level, you can use the following command to retrieve the other supported parameters.
```
python3 restore.py -h
```

Permissions required for running this restore script. The resource sections are not constrained because all users, groups, and applications information are required. IAM permissions listed in Statement1 are supporting nested calls when executing the "sso:CreateAccountAssignment" API.

``` json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Statement0",
            "Effect": "Allow",
            "Action": [
                "sso:CreateAccountAssignment",
                "sso:DescribeAccountAssignmentCreationStatus",
                "sso:ListApplications",
                "sso:CreateApplicationAssignment",
                "identitystore:ListUsers",
                "identitystore:ListGroups"
            ],
            "Resource": [
                "*"
            ]
        },
        {
            "Sid": "Statement1",
            "Effect": "Allow",
            "Action": [
                "iam:GetSAMLProvider",
                "iam:GetRole",
                "iam:ListAttachedRolePolicies",
                "iam:ListRolePolicies"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```

### Clean up the resources
Follow the [AWS documentation](https://docs.aws.amazon.com/cloud9/latest/user-guide/delete-environment.html) to delete your created Cloud9 environment.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

