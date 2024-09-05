# Attach the EC2-related policy
aws iam put-user-policy \
    --user-name Nadav.edu.devops \
    --policy-name EC2CreateVpcPolicy \
    --policy-document file://ec2-policy.json

# Attach the IAM role-related policy
aws iam put-user-policy \
    --user-name Nadav.edu.devops \
    --policy-name IAMCreateRolePolicy \
    --policy-document file://iam-policy.json
