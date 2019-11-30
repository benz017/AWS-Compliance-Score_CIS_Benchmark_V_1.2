import boto3
import time
import json
import csv
import sys
import datetime
from datetime import datetime
from multiprocessing import cpu_count, Pool
from botocore.client import Config
import re


accesskey = "<< CloudAccessKey >>"
secret_accesskey= "<< CloudSecretKey >>"
reg = "<< CloudRegion >>"

# --- Script controls ---

# CIS Benchmark version referenced. Only used in web report.
AWS_CIS_BENCHMARK_VERSION = "1.2"

# Control 1.1 - Days allowed since use of root account.
CONTROL_1_1_DAYS = 0

config = Config(connect_timeout=5, retries={'max_attempts': 0})


def return_client(s_name, region=reg):
    return boto3.client(
        s_name,
        aws_access_key_id=accesskey,
        aws_secret_access_key=secret_accesskey,
        region_name=region,
        config=config
    )

IAM_CLIENT = return_client('iam')
S3_CLIENT = return_client('s3')
EC2_CLIENT = return_client('ec2')


# --- 1 Identity and Access Management ---

# 1.1 Avoid the use of the "root" account (Scored)
def control_1_1_root_use(credreport,json):
    """Summary
    Args:
        credreport (TYPE): Description
    Returns:
        TYPE: Description
    """
    failReason = ""
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    if "Fail" in credreport:  # Report failure in control
        sys.exit(credreport)
    # Check if root is used in the last 24h
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"

    try:
        pwdDelta = (datetime.strptime(now, frm) - datetime.strptime(credreport[0]['password_last_used'], frm))
        if (pwdDelta.days == CONTROL_1_1_DAYS) & (pwdDelta.seconds > 0):  # Used within last 24h
            failReason = "Used within 24h"
            result = "False"
    except:
        if credreport[0]['password_last_used'] == "N/A" or "no_information":
            isfailure = "True"
            result="False"
        else:
            failreason="Something went wrong"
            isfailure = "True"
            result="False"

    try:
        key1Delta = (datetime.strptime(now, frm) - datetime.strptime(credreport[0]['access_key_1_last_used_date'], frm))
        if (key1Delta.days == CONTROL_1_1_DAYS) & (key1Delta.seconds > 0):  # Used within last 24h
            failReason = "Used within 24h"
            result = "False"
    except:
        if credreport[0]['access_key_1_last_used_date'] == "N/A" or "no_information":
            result = "True"
            result="False"
        else:
            failreason="Something went wrong"
            isfailure = "True"
            result="False"
    try:
        key2Delta = datetime.strptime(now, frm) - datetime.strptime(credreport[0]['access_key_2_last_used_date'], frm)
        if (key2Delta.days == CONTROL_1_1_DAYS) & (key2Delta.seconds > 0):  # Used within last 24h
            failReason = "Used within 24h"
            result = "False"
    except:
        if credreport[0]['access_key_2_last_used_date'] == "N/A" or "no_information":
            isfailure = "True"
            result="False"
        else:
            failreason="Something went wrong"
            isfailure = "True"
            result="False"
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 1.2 Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)
def control_1_2_mfa_on_password_enabled_iam(credreport,json):
    """Summary
    Args:
        credreport (TYPE): Description
    Returns:
        TYPE: Description
    """
    failReason =""
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        for i in range(len(credreport)):
            # Verify if the user have a password configured
            if credreport[i]['password_enabled'] == "true":
                # Verify if password users have MFA assigned
                if credreport[i]['mfa_active'] == "false":
                    result = "False"
                    failReason = "No MFA on users with password. "
                    offenders.append(str(credreport[i]['arn']))
    except:
        isfailure="True"
        result =""
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 1.3 Ensure credentials unused for 90 days or greater are disabled (Scored)
def control_1_3_unused_credentials(credreport,json):
    """Summary
    Args:
        credreport (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    # Get current time
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"

    # Look for unused credentails
    try:
        for i in range(len(credreport)):
            if credreport[i]['password_enabled'] != "true":
                try:
                    delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['password_last_used'], frm)
                    # Verify password have been used in the last 90 days
                    if delta.days > 90:
                        result = "False"
                        failReason = "Credentials unused > 90 days detected. "
                        offenders.append(str(credreport[i]['arn']) + ":password")
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)  # Never used
            if credreport[i]['access_key_1_active'] == "true":
                try:
                    delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_1_last_used_date'], frm)
                    # Verify password have been used in the last 90 days
                    if delta.days > 90:
                        result = "False"
                        failReason = "Credentials unused > 90 days detected. "
                        offenders.append(str(credreport[i]['arn']) + ":key1")
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
            if credreport[i]['access_key_2_active'] == "true":
                try:
                    delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_2_last_used_date'], frm)
                    # Verify password have been used in the last 90 days
                    if delta.days > 90:
                        result = "False"
                        failReason = "Credentials unused > 90 days detected. "
                        offenders.append(str(credreport[i]['arn']) + ":key2")
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json

# 1.4 Ensure access keys are rotated every 90 days or less (Scored)
def control_1_4_rotated_keys(credreport,json):
    """Summary
    Args:
        credreport (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    # Get current time
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"
    try:
        # Look for unused credentails
        for i in range(len(credreport)):
            if credreport[i]['access_key_1_active'] == "true":
                try:
                    delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_1_last_rotated'], frm)
                    # Verify keys have rotated in the last 90 days
                    if delta.days > 90:
                        result = "False"
                        failReason = "Key rotation >90 days or not used since rotation"
                        offenders.append(str(credreport[i]['arn']) + ":unrotated key1")
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
                try:
                    last_used_datetime = datetime.strptime(credreport[i]['access_key_1_last_used_date'], frm)
                    last_rotated_datetime = datetime.strptime(credreport[i]['access_key_1_last_rotated'], frm)
                    # Verify keys have been used since rotation.
                    if last_used_datetime < last_rotated_datetime:
                        result = "False"
                        failReason = "Key rotation >90 days or not used since rotation"
                        offenders.append(str(credreport[i]['arn']) + ":unused key1")
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
            if credreport[i]['access_key_2_active'] == "true":
                try:
                    delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_2_last_rotated'], frm)
                    # Verify keys have rotated in the last 90 days
                    if delta.days > 90:
                        result = "False"
                        failReason = "Key rotation >90 days or not used since rotation"
                        offenders.append(str(credreport[i]['arn']) + ":unrotated key2")
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
                try:
                    last_used_datetime = datetime.strptime(credreport[i]['access_key_2_last_used_date'], frm)
                    last_rotated_datetime = datetime.strptime(credreport[i]['access_key_2_last_rotated'], frm)
                    # Verify keys have been used since rotation.
                    if last_used_datetime < last_rotated_datetime:
                        result = "False"
                        failReason = "Key rotation >90 days or not used since rotation"
                        offenders.append(str(credreport[i]['arn']) + ":unused key2")
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 1.5 Ensure IAM password policy requires at least one uppercase letter (Scored)
def control_1_5_password_policy_uppercase(passwordpolicy,json):
    """Summary
    Args:
        passwordpolicy (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        if passwordpolicy is False:
            result = "False"
            failReason = "Account does not have a IAM password policy."
        else:
            if passwordpolicy['RequireUppercaseCharacters'] is False:
                result = "False"
                failReason = "Password policy does not require at least one uppercase letter"
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"]= "" if passwordpolicy is None or passwordpolicy is False else parse(passwordpolicy['RequireUppercaseCharacters'])
    json["IsCompliant"]=result
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json

# 1.6 Ensure IAM password policy requires at least one lowercase letter (Scored)
def control_1_6_password_policy_lowercase(passwordpolicy,json):
    """Summary
    Args:
        passwordpolicy (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        if passwordpolicy is False:
            result = "False"
            failReason = "Account does not have a IAM password policy."
        else:
            if passwordpolicy['RequireLowercaseCharacters'] is False:
                result = "False"
                failReason = "Password policy does not require at least one uppercase letter"
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = "" if passwordpolicy is None or passwordpolicy is False else parse(passwordpolicy['RequireLowercaseCharacters'])
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json

# 1.7 Ensure IAM password policy requires at least one symbol (Scored)
def control_1_7_password_policy_symbol(passwordpolicy,json):
    """Summary
    Args:
        passwordpolicy (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        if passwordpolicy is False:
            result = "False"
            failReason = "Account does not have a IAM password policy."
        else:
            if passwordpolicy['RequireSymbols'] is False:
                result = "False"
                failReason = "Password policy does not require at least one symbol"
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = "" if passwordpolicy is None or passwordpolicy is False else parse(passwordpolicy['RequireSymbols'])
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json

# 1.8 Ensure IAM password policy requires at least one number (Scored)
def control_1_8_password_policy_number(passwordpolicy,json):
    """Summary
    Args:
        passwordpolicy (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        if passwordpolicy is False:
            result = "False"
            failReason = "Account does not have a IAM password policy."
        else:
            if passwordpolicy['RequireNumbers'] is False:
                result = "False"
                failReason = "Password policy does not require at least one number"
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = "" if passwordpolicy is None or passwordpolicy is False else parse(passwordpolicy['RequireNumbers'])
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json

# 1.9 Ensure IAM password policy requires minimum length of 14 or greater (Scored)
def control_1_9_password_policy_length(passwordpolicy,json):
    """Summary
    Args:
        passwordpolicy (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        if passwordpolicy is False:
            result = "False"
            failReason = "Account does not have a IAM password policy."
        else:
            if passwordpolicy['MinimumPasswordLength'] < 14:
                result = "False"
                failReason = "Password policy does not require at least 14 characters"
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = "" if passwordpolicy is None or passwordpolicy is False else parse(passwordpolicy['MinimumPasswordLength'])
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json

# 1.10 Ensure IAM password policy prevents password reuse (Scored)
def control_1_10_password_policy_reuse(passwordpolicy,json):
    """Summary
    Args:
        passwordpolicy (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        if passwordpolicy is False:
            result = "False"
            failReason = "Account does not have a IAM password policy."
        else:
            if passwordpolicy['PasswordReusePrevention'] != 24:
                result = "False"
                failReason = "Password policy does not prevent reusing last 24 passwords"
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = "" if passwordpolicy is None or passwordpolicy is False else parse(passwordpolicy['PasswordReusePrevention'])
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json

# 1.11 Ensure IAM password policy expires passwords within 90 days or less (Scored)
def control_1_11_password_policy_expire(passwordpolicy,json):
    """Summary
    Args:
        passwordpolicy (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        if passwordpolicy is False:
            result = "False"
            failReason = "Account does not have a IAM password policy."
        else:
            if passwordpolicy['ExpirePasswords'] is True:
                if 0 < passwordpolicy['MaxPasswordAge'] > 90:
                    result = "False"
                    failReason = "Password policy does not expire passwords after 90 days or less"
            else:
                result = "False"
                failReason = "Password policy does not expire passwords after 90 days or less"
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = "" if passwordpolicy is None else parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json

# 1.12 Ensure no root account access key exists (Scored)
def control_1_12_root_key_exists(credreport,json):
    """Summary
    Args:
        credreport (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        if (credreport[0]['access_key_1_active'] == "true") or (credreport[0]['access_key_2_active'] == "true"):
            result = "False"
            failReason = "Root have active access keys"
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json

# 1.13 Ensure MFA is enabled for the "root" account (Scored)
def control_1_13_root_mfa_enabled(json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        response = IAM_CLIENT.get_account_summary()
        if response['SummaryMap']['AccountMFAEnabled'] != 1:
            result = "False"
            failReason = "Root account not using MFA"
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 1.14 Ensure hardware MFA is enabled for the "root" account (Scored)
def control_1_14_root_hardware_mfa_enabled(json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        # First verify that root is using MFA (avoiding false positive)
        response = IAM_CLIENT.get_account_summary()
        if response['SummaryMap']['AccountMFAEnabled'] == 1:
            paginator = IAM_CLIENT.get_paginator('list_virtual_mfa_devices')
            response_iterator = paginator.paginate(
                AssignmentStatus='Any',
            )
            pagedResult = []
            for page in response_iterator:
                for n in page['VirtualMFADevices']:
                    pagedResult.append(n)
            if "mfa/root-account-mfa-device" in str(pagedResult):
                failReason = "Root account not using hardware MFA"
                result = "False"
        else:
            result = "False"
            failReason = "Root account not using MFA"
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 1.15 Ensure security questions are registered in the AWS account (Not Scored/Manual)
def control_1_15_security_questions_registered(json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = "False"
    offenders = []
    scored = "False"
    isfailure = "False"
    failReason = "Control not implemented using API, please verify manually"
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 1.16 Ensure IAM policies are attached only to groups or roles (Scored)
def control_1_16_no_policies_on_iam_users(json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        paginator = IAM_CLIENT.get_paginator('list_users')
        response_iterator = paginator.paginate()
        pagedResult = []
        for page in response_iterator:
            for n in page['Users']:
                pagedResult.append(n)
        offenders = []
        for n in pagedResult:
            policies = IAM_CLIENT.list_user_policies(
                UserName=n['UserName'],
                MaxItems=1
            )
            if policies['PolicyNames'] != []:
                result = "False"
                failReason = "IAM user have inline policy attached"
                offenders.append(str(n['Arn']))
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json

# 1.17 Maintain current contact details (Scored)
def control_1_17_maintain_current_contact_details(json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = "False"
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Control not implemented using API, please verify manually"
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 1.18 Ensure security contact information is registered (Scored)
def control_1_18_ensure_security_contact_details(json):
    """Summary
   Returns:
        TYPE: Description
    """
    result = "False"
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Control not implemented using API, please verify manually"
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json

# 1.19 Ensure IAM instance roles are used for AWS resource access from instances (Scored)
def control_1_19_ensure_iam_instance_roles_used(json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Instance not assigned IAM role for EC2"
    response = EC2_CLIENT.describe_instances()
    try:
        for n, _ in enumerate(response['Reservations']):
            try:
                if response['Reservations'][n]['Instances'][0]['IamInstanceProfile']:
                    isfailure = "True"
                    result="False"
            except:
                result = "False"
                offenders.append(str(response['Reservations'][n]['Instances'][0]['InstanceId']))
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 1.20 Ensure a support role has been created to manage incidents with AWS Support (Scored)
def control_1_20_ensure_incident_management_roles(json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        response = IAM_CLIENT.list_entities_for_policy(
            PolicyArn='arn:aws:iam::aws:policy/AWSSupportAccess'
        )
        if (len(response['PolicyGroups']) + len(response['PolicyUsers']) + len(response['PolicyRoles'])) == 0:
            result = "False"
            failReason = "No user, group or role assigned AWSSupportAccess"
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
        failReason = "AWSSupportAccess policy not created"
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 1.21 Do not setup access keys during initial user setup for all IAM users that have a console password (Not Scored)
def control_1_21_no_active_initial_access_keys_with_iam_user(credreport,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "False"
    isfailure = "False"
    try:
        for n, _ in enumerate(credreport):
            if (credreport[n]['access_key_1_active'] or credreport[n]['access_key_2_active'] == 'true') and n > 0:
                response = IAM_CLIENT.list_access_keys(
                    UserName=str(credreport[n]['user'])
                )
                for m in response['AccessKeyMetadata']:
                    if re.sub(r"\s", "T", str(m['CreateDate'])) == credreport[n]['user_creation_time']:
                        result = "False"
                        failReason = "Users with keys created at user creation time found"
                        offenders.append(str(credreport[n]['arn']) + ":" + str(m['AccessKeyId']))
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 1.22  Ensure IAM policies that allow full "*:*" administrative privileges are not created (Scored)
def control_1_22_no_overly_permissive_policies(json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        paginator = IAM_CLIENT.get_paginator('list_policies')
        response_iterator = paginator.paginate(
            Scope='Local',
            OnlyAttached=False,
        )
        pagedResult = []
        for page in response_iterator:
            for n in page['Policies']:
                pagedResult.append(n)
        for m in pagedResult:
            policy = IAM_CLIENT.get_policy_version(
                PolicyArn=m['Arn'],
                VersionId=m['DefaultVersionId']
            )

            statements = []
            # a policy may contain a single statement, a single statement in an array, or multiple statements in an array
            if isinstance(policy['PolicyVersion']['Document']['Statement'], list):
                for statement in policy['PolicyVersion']['Document']['Statement']:
                    statements.append(statement)
            else:
                statements.append(policy['PolicyVersion']['Document']['Statement'])

            for n in statements:
                # a policy statement has to contain either an Action or a NotAction
                if 'Action' in n.keys() and n['Effect'] == 'Allow':
                    if ("'*'" in str(n['Action']) or str(n['Action']) == "*") and ("'*'" in str(n['Resource']) or str(n['Resource']) == "*"):
                        result = "False"
                        failReason = "Found full administrative policy"
                        offenders.append(str(m['Arn']))
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# --- 2 Logging ---

# 2.1 Ensure CloudTrail is enabled in all regions (Scored)
def control_2_1_ensure_cloud_trail_all_regions(cloudtrails,json):
    """Summary
    Args:
        cloudtrails (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                if o['IsMultiRegionTrail']:
                    client = return_client('cloudtrail', region=m)
                    response = client.get_trail_status(
                        Name=o['TrailARN']
                    )
                    if response['IsLogging'] is False:
                        result = "False"
                        break
                else:
                    result="False"
                    break
        if result == "False":
            failReason = "No enabled multi region trails found"
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 2.2 Ensure CloudTrail log file validation is enabled (Scored)
def control_2_2_ensure_cloudtrail_validation(cloudtrails,json):
    """Summary
    Args:
        cloudtrails (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                if o['LogFileValidationEnabled'] is False:
                    result = "False"
                    failReason = "CloudTrails without log file validation discovered"
                    offenders.append(str(o['TrailARN']))
        offenders = list(set(offenders))
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 2.3 Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)
def control_2_3_ensure_cloudtrail_bucket_not_public(cloudtrails,json):
    """Summary
    Args:
        cloudtrails (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                #  We only want to check cases where there is a bucket
                if "S3BucketName" in str(o):
                    try:
                        response = S3_CLIENT.get_bucket_acl(Bucket=o['S3BucketName'])
                        for p in response['Grants']:
                            # print("Grantee is " + str(p['Grantee']))
                            if re.search(r'(global/AllUsers|global/AuthenticatedUsers)', str(p['Grantee'])):
                                result = "False"
                                offenders.append(str(o['TrailARN']) + ":PublicBucket")
                                if "Publically" not in failReason:
                                    failReason = failReason + "Publically accessible CloudTrail bucket discovered."
                    except Exception as e:
                        result = "False"
                        if "AccessDenied" in str(e):
                            offenders.append(str(o['TrailARN']) + ":AccessDenied")
                            if "Missing" not in failReason:
                                failReason = "Missing permissions to verify bucket ACL. " + failReason
                        elif "NoSuchBucket" in str(e):
                            offenders.append(str(o['TrailARN']) + ":NoBucket")
                            if "Trailbucket" not in failReason:
                                failReason = "Trailbucket doesn't exist. " + failReason
                        else:
                            offenders.append(str(o['TrailARN']) + ":CannotVerify")
                            if "Cannot" not in failReason:
                                failReason = "Cannot verify bucket ACL. " + failReason
                else:
                    result = "False"
                    offenders.append(str(o['TrailARN']) + "NoS3Logging")
                    failReason = "Cloudtrail not configured to log to S3. " + failReason
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 2.4 Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)
def control_2_4_ensure_cloudtrail_cloudwatch_logs_integration(cloudtrails,json):
    """Summary
    Args:
        cloudtrails (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if "arn:aws:logs" not in o['CloudWatchLogsLogGroupArn']:
                        result = "False"
                        failReason = "CloudTrails without CloudWatch Logs discovered"
                        offenders.append(str(o['TrailARN']))

                except:
                    result = "False"
                    failReason = "CloudTrails without CloudWatch Logs discovered"
                    offenders.append(str(o['TrailARN']))
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 2.5 Ensure AWS Config is enabled in all regions (Scored)
def control_2_5_ensure_config_all_regions(regions,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    globalConfigCapture = "False"  # Only one region needs to capture global events
    try:
        for n in regions:
            configClient = return_client('config', region=n)
            response = configClient.describe_configuration_recorder_status()

            # Get recording status
            try:
                if response['ConfigurationRecordersStatus'][0]['recording'] != "True":
                    result = "False"
                    failReason = "Config not capturing all/global events or delivery channel errors"
                    offenders.append(str(n) + ":NotRecording")
            except Exception as e:
                isfailure = "True"
                result="False"
                failReason=str(e)
                failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
                offenders.append(str(n) + ":NotRecording")
                continue

            # Verify that each region is capturing all events
            response = configClient.describe_configuration_recorders()
            try:
                if response['ConfigurationRecorders'][0]['recordingGroup']['allSupported'] != "True":
                    result = "False"
                    failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
                    offenders.append(str(n) + ":NotAllEvents")
            except Exception as e:
                isfailure = "True"
                result="False"
                failReason=str(e)# This indicates that Config is disabled in the region and will be captured above.

            # Check if region is capturing global events. Fail is verified later since only one region needs to capture them.
            try:
                if response['ConfigurationRecorders'][0]['recordingGroup']['includeGlobalResourceTypes'] == "True":
                    globalConfigCapture = "True"
            except Exception as e:
                isfailure = "True"
                result="False"
                failReason=str(e)

            # Verify the delivery channels
            response = configClient.describe_delivery_channel_status()
            try:
                if response['DeliveryChannelsStatus'][0]['configHistoryDeliveryInfo']['lastStatus'] != "SUCCESS":
                    result = "False"
                    failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
                    offenders.append(str(n) + ":S3orSNSDelivery")
            except Exception as e:
                isfailure = "True"
                result="False"
                failReason=str(e)  # Will be captured by earlier rule
            try:
                if response['DeliveryChannelsStatus'][0]['configStreamDeliveryInfo']['lastStatus'] != "SUCCESS":
                    result = "False"
                    failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
                    offenders.append(str(n) + ":SNSDelivery")
            except Exception as e:
                isfailure = "True"
                result="False"
                failReason=str(e)# Will be captured by earlier rule
    except:
        isfailure = "True"
        result = ""
        failReason = "Config not configured for your account"
    # Verify that global events is captured by any region

    if globalConfigCapture == "False":
        if isfailure == "True":
            result="False"
        else:
            result = "False"
            failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason

    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 2.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)
def control_2_6_ensure_cloudtrail_bucket_logging(cloudtrails,json):
    """Summary
    Args:
        cloudtrails (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                # it is possible to have a cloudtrail configured with a nonexistant bucket
                try:
                    response = S3_CLIENT.get_bucket_logging(Bucket=o['S3BucketName'])
                except:
                    result = "False"
                    failReason = "Cloudtrail not configured to log to S3. "
                    offenders.append(str(o['TrailARN']))
                try:
                    if response['LoggingEnabled']:
                        isfailure = "True"
                        result="False"
                except:
                    result = "False"
                    failReason = failReason + "CloudTrail S3 bucket without logging discovered"
                    offenders.append("Trail:" + str(o['TrailARN']) + " - S3Bucket:" + str(o['S3BucketName']))
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 2.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)
def control_2_7_ensure_cloudtrail_encryption_kms(cloudtrails,json):
    """Summary
    Args:
        cloudtrails (TYPE): Description
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if not o['KmsKeyId']:
                        result = "False"
                        failReason = "CloudTrail not using KMS CMK for encryption discovered"
                except:
                    result = "False"
                    failReason = "CloudTrail not using KMS CMK for encryption discovered"
                    offenders.append("Trail:" + str(o['TrailARN']))
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json

# 2.8 Ensure rotation for customer created CMKs is enabled (Scored)
def control_2_8_ensure_kms_cmk_rotation(regions,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        for n in regions:
            kms_client = return_client('kms', region=n)
            paginator = kms_client.get_paginator('list_keys')
            response_iterator = paginator.paginate()
            for page in response_iterator:
                for n in page['Keys']:
                    try:
                        rotationStatus = kms_client.get_key_rotation_status(KeyId=n['KeyId'])
                        if rotationStatus['KeyRotationEnabled'] == "False":
                            keyDescription = kms_client.describe_key(KeyId=n['KeyId'])
                            if "Default master key that protects my" not in str(keyDescription['KeyMetadata']['Description']):  # Ignore service keys
                                result = "False"
                                failReason = "KMS CMK rotation not enabled"
                                offenders.append("Key:" + str(keyDescription['KeyMetadata']['Arn']))
                    except Exception as e:
                        isfailure = "True"
                        result="False"
                        failReason=str(e)  # Ignore keys without permission, for example ACM key
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json

# --- Monitoring ---

# 3.1 Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)
def control_3_1_ensure_log_metric_filter_unauthorized_api_calls(cloudtrails,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Incorrect log metric alerts for unauthorized_api_calls"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = return_client('logs', region=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.errorCode\s*=\s*\"?\*UnauthorizedOperation(\"|\)|\s)", "\$\.errorCode\s*=\s*\"?AccessDenied\*(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern']),json):
                                cwclient = return_client('cloudwatch', region=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                snsClient = return_client('sns', region=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )
                                if len(subscribers['Subscriptions']) == 0:
                                    result = "False"
                                    failReason = ""
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 3.2 Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)
def control_3_2_ensure_log_metric_filter_console_signin_no_mfa(cloudtrails,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Incorrect log metric alerts for management console signin without MFA"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = return_client('logs', region=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?ConsoleLogin(\"|\)|\s)", "\$\.additionalEventData\.MFAUsed\s*\!=\s*\"?Yes"]
                            if find_in_string(patterns, str(p['filterPattern']),json):
                                cwclient = return_client('cloudwatch', region=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                snsClient = return_client('sns', region=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )
                                if len(subscribers['Subscriptions']) == 0:
                                    result = "False"
                                    failReason = ""
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 3.3 Ensure a log metric filter and alarm exist for usage of "root" account (Scored)
def control_3_3_ensure_log_metric_filter_root_usage(cloudtrails,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Incorrect log metric alerts for root usage"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = return_client('logs', region=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.userIdentity\.type\s*=\s*\"?Root", "\$\.userIdentity\.invokedBy\s*NOT\s*EXISTS", "\$\.eventType\s*\!=\s*\"?AwsServiceEvent(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern']),json):
                                cwclient = return_client('cloudwatch', region=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                snsClient = return_client('sns', region=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )
                                if len(subscribers['Subscriptions']) == 0:
                                    result = "False"
                                    failReason = ""
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 3.4 Ensure a log metric filter and alarm exist for IAM policy changes  (Scored)
def control_3_4_ensure_log_metric_iam_policy_change(cloudtrails,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Incorrect log metric alerts for IAM policy changes"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = return_client('logs', region=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?DeleteGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreatePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeletePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreatePolicyVersion(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeletePolicyVersion(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachGroupPolicy(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern']),json):
                                cwclient = return_client('cloudwatch', region=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                snsClient = return_client('sns', region=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )
                                if len(subscribers['Subscriptions']) == 0:
                                    result = "False"
                                    failReason = ""
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 3.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)
def control_3_5_ensure_log_metric_cloudtrail_configuration_changes(cloudtrails,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Incorrect log metric alerts for CloudTrail configuration changes"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = return_client('logs', region=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?CreateTrail(\"|\)|\s)", "\$\.eventName\s*=\s*\"?UpdateTrail(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteTrail(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StartLogging(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StopLogging(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern']),json):
                                cwclient = return_client('cloudwatch', region=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                snsClient = return_client('sns', region=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )
                                if len(subscribers['Subscriptions']) == 0:
                                    result = "False"
                                    failReason = ""
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)
def control_3_6_ensure_log_metric_console_auth_failures(cloudtrails,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Ensure a log metric filter and alarm exist for console auth failures"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?ConsoleLogin(\"|\)|\s)", "\$\.errorMessage\s*=\s*\"?Failed authentication(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern']),json):
                                cwclient = return_client('cloudwatch', region=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                snsClient = return_client('sns', region=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )
                                if len(subscribers['Subscriptions']) == 0:
                                    result = "False"
                                    failReason = ""
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 3.7 Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)
def control_3_7_ensure_log_metric_disabling_scheduled_delete_of_kms_cmk(cloudtrails,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Ensure a log metric filter and alarm exist for disabling or scheduling deletion of KMS CMK"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = return_client('logs', region=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventSource\s*=\s*\"?kms\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisableKey(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ScheduleKeyDeletion(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern']),json):
                                cwclient = return_client('cloudwatch', region=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                snsClient = return_client('sns', region=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )
                                if len(subscribers['Subscriptions']) == 0:
                                    result = "False"
                                    failReason = ""
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 3.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)
def control_3_8_ensure_log_metric_s3_bucket_policy_changes(cloudtrails,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Ensure a log metric filter and alarm exist for S3 bucket policy changes"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = return_client('logs', region=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventSource\s*=\s*\"?s3\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketAcl(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketCors(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketLifecycle(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketReplication(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketCors(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketLifecycle(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketReplication(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern']),json):
                                cwclient = return_client('cloudwatch', region=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                snsClient = return_client('sns', region=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )
                                if len(subscribers['Subscriptions']) == 0:
                                    result = "False"
                                    failReason = ""
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored)
def control_3_9_ensure_log_metric_config_configuration_changes(cloudtrails,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Ensure a log metric filter and alarm exist for for AWS Config configuration changes"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = return_client('logs', region=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventSource\s*=\s*\"?config\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StopConfigurationRecorder(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteDeliveryChannel(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutDeliveryChannel(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutConfigurationRecorder(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern']),json):
                                cwclient = return_client('cloudwatch', region=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                snsClient = return_client('sns', region=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )
                                if len(subscribers['Subscriptions']) == 0:
                                    result = "False"
                                    failReason = ""
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 3.10 Ensure a log metric filter and alarm exist for security group changes (Scored)
def control_3_10_ensure_log_metric_security_group_changes(cloudtrails,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Ensure a log metric filter and alarm exist for security group changes"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = return_client('logs', region=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?AuthorizeSecurityGroupIngress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AuthorizeSecurityGroupEgress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?RevokeSecurityGroupIngress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?RevokeSecurityGroupEgress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateSecurityGroup(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteSecurityGroup(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern']),json):
                                cwclient = return_client('cloudwatch', region=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                snsClient = return_client('sns', region=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )
                                if len(subscribers['Subscriptions']) == 0:
                                    result = "False"
                                    failReason = ""
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 3.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)
def control_3_11_ensure_log_metric_nacl(cloudtrails,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = return_client('logs', region=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?CreateNetworkAcl(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateNetworkAclEntry(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteNetworkAcl(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteNetworkAclEntry(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceNetworkAclEntry(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceNetworkAclAssociation(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern']),json):
                                cwclient = return_client('cloudwatch', region=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                snsClient = return_client('sns', region=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )
                                if len(subscribers['Subscriptions']) == 0:
                                    result = "False"
                                    failReason = ""
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 3.12 Ensure a log metric filter and alarm exist for changes to network gateways (Scored)
def control_3_12_ensure_log_metric_changes_to_network_gateways(cloudtrails,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Ensure a log metric filter and alarm exist for changes to network gateways"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = return_client('logs', region=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?CreateCustomerGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteCustomerGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachInternetGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateInternetGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteInternetGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachInternetGateway(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern']),json):
                                cwclient = return_client('cloudwatch', region=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                snsClient = return_client('sns', region=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )
                                if len(subscribers['Subscriptions']) == 0:
                                    result = "False"
                                    failReason = ""
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 3.13 Ensure a log metric filter and alarm exist for route table changes (Scored)
def control_3_13_ensure_log_metric_changes_to_route_tables(cloudtrails,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Ensure a log metric filter and alarm exist for route table changes"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client =return_client('logs', region=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?CreateRoute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateRouteTable(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceRoute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceRouteTableAssociation(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRouteTable(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRoute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisassociateRouteTable(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern']),json):
                                cwclient = return_client('cloudwatch', region=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                snsClient = return_client('sns', region=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )
                                if len(subscribers['Subscriptions']) == 0:
                                    result = "False"
                                    failReason = ""
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 3.14 Ensure a log metric filter and alarm exist for VPC changes (Scored)
def control_3_14_ensure_log_metric_changes_to_vpc(cloudtrails,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    failReason = "Ensure a log metric filter and alarm exist for VPC changes"
    try:
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = return_client('logs', region=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?CreateVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ModifyVpcAttribute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AcceptVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?RejectVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachClassicLinkVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachClassicLinkVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisableVpcClassicLink(\"|\)|\s)", "\$\.eventName\s*=\s*\"?EnableVpcClassicLink(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern']),json):
                                cwclient = return_client('cloudwatch', region=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                snsClient = return_client('sns', region=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )
                                if len(subscribers['Subscriptions']) == 0:
                                    result = "False"
                                    failReason = ""
                except Exception as e:
                    isfailure = "True"
                    result="False"
                    failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# --- Networking ---
# 4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)
def control_4_1_ensure_ssh_not_open_to_world(regions,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        for n in regions:
            client = return_client('ec2', region=n)
            response = client.describe_security_groups()
            for m in response['SecurityGroups']:
                if "0.0.0.0/0" in str(m['IpPermissions']):
                    for o in m['IpPermissions']:
                        try:
                            if int(o['FromPort']) <= 22 <= int(o['ToPort']) and '0.0.0.0/0' in str(o['IpRanges']):
                                result = "False"
                                failReason = "Found Security Group with port 22 open to the world (0.0.0.0/0)"
                                offenders.append(str(m['GroupId']))
                        except:
                            if str(o['IpProtocol']) == "-1" and '0.0.0.0/0' in str(o['IpRanges']):
                                result = "False"
                                failReason = "Found Security Group with port 22 open to the world (0.0.0.0/0)"
                                offenders.append(str(n) + " : " + str(m['GroupId']))
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)
def control_4_2_ensure_rdp_not_open_to_world(regions,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        for n in regions:
            client = return_client('ec2', region=n)
            response = client.describe_security_groups()
            for m in response['SecurityGroups']:
                if "0.0.0.0/0" in str(m['IpPermissions']):
                    for o in m['IpPermissions']:
                        try:
                            if int(o['FromPort']) <= 3389 <= int(o['ToPort']) and '0.0.0.0/0' in str(o['IpRanges']):
                                result = "False"
                                failReason = "Found Security Group with port 3389 open to the world (0.0.0.0/0)"
                                offenders.append(str(m['GroupId']))
                        except:
                            if str(o['IpProtocol']) == "-1" and '0.0.0.0/0' in str(o['IpRanges']):
                                result = "False"
                                failReason = "Found Security Group with port 3389 open to the world (0.0.0.0/0)"
                                offenders.append(str(n) + " : " + str(m['GroupId']))
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 4.3 Ensure the default security group of every VPC restricts all traffic (Scored)
def control_4_3_ensure_default_security_groups_restricts_traffic(regions,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "True"
    isfailure = "False"
    try:
        for n in regions:
            client = return_client('ec2', region=n)
            response = client.describe_security_groups(
                Filters=[
                    {
                        'Name': 'group-name',
                        'Values': [
                            'default',
                        ]
                    },
                ]
            )
            for m in response['SecurityGroups']:
                if not (len(m['IpPermissions']) + len(m['IpPermissionsEgress'])) == 0:
                    result = "False"
                    failReason = "Default security groups with ingress or egress rules discovered"
                    offenders.append(str(n) + " : " + str(m['GroupId']))
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] ==  json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


# 4.4 Ensure routing tables for VPC peering are "least access" (Not Scored)
def control_4_4_ensure_route_tables_are_least_access(regions,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    failReason = ""
    offenders = []
    scored = "False"
    isfailure = "False"
    try:
        for n in regions:
            client = return_client('ec2', region=n)
            response = client.describe_route_tables()
            for m in response['RouteTables']:
                for o in m['Routes']:
                    try:
                        if o['VpcPeeringConnectionId']:
                            if int(str(o['DestinationCidrBlock']).split("/", 1)[1]) < 24:
                                result = "False"
                                failReason = "Large CIDR block routed to peer discovered, please investigate"
                                offenders.append(str(n) + " : " + str(m['RouteTableId']))
                    except Exception as e:
                        isfailure = "True"
                        result="False"
                        failReason=str(e)
    except Exception as e:
        isfailure = "True"
        result="False"
        failReason=str(e)
    failReason = failReason + "|| Offenders: || " + " || ".join(offenders) if offenders else failReason
    json["CurrentValue"] = parse(result)
    json["IsCompliant"] = "True" if json["ExpectedValue"] == json["CurrentValue"] else "False"
    json["Remarks"] = failReason
    json["ScoredControl"] = scored
    json["IsFailure"]=isfailure
    return json


def get_cred_report():
    """Summary
    Returns:
        TYPE: Description
    """
    x = 0
    status = ""
    while IAM_CLIENT.generate_credential_report()['State'] != "COMPLETE":
        time.sleep(2)
        x += 1
        # If no credentail report is delivered within this time fail the check.
        if x > 10:
            status = "Fail: rootUse - no CredentialReport available."
            break
    if "Fail" in status:
        return status
    response = IAM_CLIENT.get_credential_report()
    report = []
    lk=[]
    for i in response['Content'].splitlines():
        i = i.decode('utf-8')

        lk.append(i+"\n")
    reader = csv.DictReader(lk,delimiter=",")
    for row in reader:
        report.append(dict(row))
    # Verify if root key's never been used, if so add N/A

    try:
        if report[0]['access_key_1_last_used_date']:
            isfailure = "True"
            result="False"
    except:
        report[0]['access_key_1_last_used_date'] = "N/A"
    try:
        if report[0]['access_key_2_last_used_date']:
            isfailure = "True"
            result="False"
    except:
        report[0]['access_key_2_last_used_date'] = "N/A"

    return report


def get_account_password_policy():
    """Check if a IAM password policy exists, if not return false
    Returns:
        Account IAM password policy or "False"
    """
    IAM_CLIENT = return_client('iam')
    try:
        response = IAM_CLIENT.get_account_password_policy()
        return response['PasswordPolicy']
    except Exception as e:
        if "cannot be found" in str(e):
            return "False"


def get_regions():
    """Summary
    Returns:
        TYPE: Description
    """
    client = return_client('ec2')
    region_response = client.describe_regions()
    regions = [region['RegionName'] for region in region_response['Regions']]
    return regions


def get_cloudtrails(regions):
    """Summary
    Returns:
        TYPE: Description
    """
    trails = dict()
    for n in regions:
        client = return_client('cloudtrail', region=n)
        response = client.describe_trails()
        temp = []
        for m in response['trailList']:
            if m['IsMultiRegionTrail'] == "True":
                if m['HomeRegion'] == n:
                    temp.append(m)
            else:
                temp.append(m)
        if len(temp) > 0:
            trails[n] = temp
    return trails


def find_in_string(pattern,target,json):
    """Summary
    Returns:
        TYPE: Description
    """
    result = json["ExpectedValue"]
    json["CurrentValue"] = ""
    for n in pattern:
        if not re.search(n, target):
            result = "False"
            break
    return result


def parse(ch):
    if isinstance(ch,(int,float,bool)) == True:
        return str(ch)
    else:
        return ch


def control_map(c_num):
    controls = {
        1.1: "control_1_1_root_use",
        1.2: "control_1_2_mfa_on_password_enabled_iam",
        1.3: "control_1_3_unused_credentials",
        1.4: "control_1_4_rotated_keys",
        1.5: "control_1_5_password_policy_uppercase",
        1.6: "control_1_6_password_policy_lowercase",
        1.7: "control_1_7_password_policy_symbol",
        1.8: "control_1_8_password_policy_number",
        1.9: "control_1_9_password_policy_length",
        1.10: "control_1_10_password_policy_reuse",
        1.11: "control_1_11_password_policy_expire",
        1.12: "control_1_12_root_key_exists",
        1.13: "control_1_13_root_mfa_enabled",
        1.14: "control_1_14_root_hardware_mfa_enabled",
        1.15: "control_1_15_security_questions_registered",
        1.16: "control_1_16_no_policies_on_iam_users",
        1.17: "control_1_17_maintain_current_contact_details",
        1.18: "control_1_18_ensure_security_contact_details",
        1.19: "control_1_19_ensure_iam_instance_roles_used",
        1.20: "control_1_20_ensure_incident_management_roles",
        1.21: "control_1_21_no_active_initial_access_keys_with_iam_user",
        1.22: "control_1_22_no_overly_permissive_policies",
        2.1: "control_2_1_ensure_cloud_trail_all_regions",
        2.2: "control_2_2_ensure_cloudtrail_validation",
        2.3: "control_2_3_ensure_cloudtrail_bucket_not_public",
        2.4: "control_2_4_ensure_cloudtrail_cloudwatch_logs_integration",
        2.5: "control_2_5_ensure_config_all_regions",
        2.6: "control_2_6_ensure_cloudtrail_bucket_logging",
        2.7: "control_2_7_ensure_cloudtrail_encryption_kms",
        2.8: "control_2_8_ensure_kms_cmk_rotation",
        3.1: "control_3_1_ensure_log_metric_filter_unauthorized_api_calls",
        3.2: "control_3_2_ensure_log_metric_filter_console_signin_no_mfa",
        3.3: "control_3_3_ensure_log_metric_filter_root_usage",
        3.4: "control_3_4_ensure_log_metric_iam_policy_change",
        3.5: "control_3_5_ensure_log_metric_cloudtrail_configuration_changes",
        3.6: "control_3_6_ensure_log_metric_console_auth_failures",
        3.7: "control_3_7_ensure_log_metric_disabling_scheduled_delete_of_kms_cmk",
        3.8: "control_3_8_ensure_log_metric_s3_bucket_policy_changes",
        3.9: "control_3_9_ensure_log_metric_config_configuration_changes",
        3.10: "control_3_10_ensure_log_metric_security_group_changes",
        3.11: "control_3_11_ensure_log_metric_nacl",
        3.12: "control_3_12_ensure_log_metric_changes_to_network_gateways",
        3.13: "control_3_13_ensure_log_metric_changes_to_route_tables",
        3.14: "control_3_14_ensure_log_metric_changes_to_vpc",
        4.1: "control_4_1_ensure_ssh_not_open_to_world",
        4.2: "control_4_2_ensure_rdp_not_open_to_world",
        4.3: "control_4_3_ensure_default_security_groups_restricts_traffic",
        4.4: "control_4_4_ensure_route_tables_are_least_access:",
    }
    dependencies = {
        "control_1_1_root_use":"get_cred_report",
        "control_1_2_mfa_on_password_enabled_iam":"get_cred_report",
        "control_1_3_unused_credentials":"get_cred_report",
        "control_1_4_rotated_keys":"get_cred_report",
        "control_1_5_password_policy_uppercase":"get_account_password_policy",
        "control_1_6_password_policy_lowercase":"get_account_password_policy",
        "control_1_7_password_policy_symbol":"get_account_password_policy",
        "control_1_8_password_policy_number":"get_account_password_policy",
        "control_1_9_password_policy_length":"get_account_password_policy",
        "control_1_10_password_policy_reuse":"get_account_password_policy",
        "control_1_11_password_policy_expire":"get_account_password_policy",
        "control_1_12_root_key_exists":"get_cred_report",
        "control_1_13_root_mfa_enabled":"",
        "control_1_14_root_hardware_mfa_enabled":"",
        "control_1_15_security_questions_registered":"",
        "control_1_16_no_policies_on_iam_users":"",
        "control_1_17_maintain_current_contact_details":"",
        "control_1_18_ensure_security_contact_details":"",
        "control_1_19_ensure_iam_instance_roles_used":"",
        "control_1_20_ensure_incident_management_roles":"",
        "control_1_21_no_active_initial_access_keys_with_iam_user":"get_cred_report",
        "control_1_22_no_overly_permissive_policies":"",
        "control_2_1_ensure_cloud_trail_all_regions":"get_cloudtrails",
        "control_2_2_ensure_cloudtrail_validation":"get_cloudtrails",
        "control_2_3_ensure_cloudtrail_bucket_not_public":"get_cloudtrails",
        "control_2_4_ensure_cloudtrail_cloudwatch_logs_integration":"get_cloudtrails",
        "control_2_5_ensure_config_all_regions":"get_cloudtrails",
        "control_2_6_ensure_cloudtrail_bucket_logging":"get_cloudtrails",
        "control_2_7_ensure_cloudtrail_encryption_kms":"get_cloudtrails",
        "control_2_8_ensure_kms_cmk_rotation":"get_regions",
        "control_3_1_ensure_log_metric_filter_unauthorized_api_calls":"get_cloudtrails",
        "control_3_2_ensure_log_metric_filter_console_signin_no_mfa":"get_cloudtrails",
        "control_3_3_ensure_log_metric_filter_root_usage":"get_cloudtrails",
        "control_3_4_ensure_log_metric_iam_policy_change":"get_cloudtrails",
        "control_3_5_ensure_log_metric_cloudtrail_configuration_changes":"get_cloudtrails",
        "control_3_6_ensure_log_metric_console_auth_failures":"get_cloudtrails",
        "control_3_7_ensure_log_metric_disabling_scheduled_delete_of_kms_cmk":"get_cloudtrails",
        "control_3_8_ensure_log_metric_s3_bucket_policy_changes":"get_cloudtrails",
        "control_3_9_ensure_log_metric_config_configuration_changes":"get_cloudtrails",
        "control_3_10_ensure_log_metric_security_group_changes":"get_cloudtrails",
        "control_3_11_ensure_log_metric_nacl":"get_cloudtrails",
        "control_3_12_ensure_log_metric_changes_to_network_gateways":"get_cloudtrails",
        "control_3_13_ensure_log_metric_changes_to_route_tables":"get_cloudtrails",
        "control_3_14_ensure_log_metric_changes_to_vpc":"get_cloudtrails",
        "control_4_1_ensure_ssh_not_open_to_world":"get_regions",
        "control_4_2_ensure_rdp_not_open_to_world":"get_regions",
        "control_4_3_ensure_default_security_groups_restricts_traffic":"get_regions",
        "control_4_4_ensure_route_tables_are_least_access:":"get_regions",
    }
    control = controls.get(c_num)
    dependency = dependencies.get(control)
    return control,dependency


def compliance_score(output):
    scored = notscored = count = 0
    for x in json.loads(output):
        count+=1
        if x["ScoredControl"] == "True":
            if x["IsCompliant"] == "True":
                scored += 1
        else:
            if x["IsCompliant"] == "True":
                notscored += 0.5
    totalscore = ((scored+notscored)/count)*100
    return totalscore


def json_input(x):
    control, dependency = control_map(x["ControlNumber"])
    if dependency != "":
        if dependency == 'get_cloudtrails':
            a = globals()[dependency](get_regions())
        else:
            a = globals()[dependency]()
        f = globals()[control](a, x)
    else:
        f = globals()[control](x)
    return f


if __name__ == "__main__":
    json_list=[]
    timeout = 10
    num_workers = int(cpu_count() - 2)
    pool = Pool(num_workers)
    input_json_data = << INPUT JSON >>
    for row in input_json_data:
        result = pool.apply_async(json_input, args=(row,))
        json_list.append(result.get())
    pool.close()
    pool.join()
    json_output = json.dumps(json_list)
    score = compliance_score(json_output)
    print(json_output)
    print("=======================================================")
    print("============= COMPLIANCE SCORE : "+str(score)+"% ================")
    print("=======================================================")