locals {
  well_architected_iam_common_tags = merge(local.aws_well_architected_common_tags, {
    service = "AWS/IAM"
  })
}

control "iam_root_user_mfa_enabled" {
  title       = "IAM root user MFA should be enabled"
  description = "Manage access to resources in the AWS Cloud by ensuring MFA is enabled for the root user."
  query       = query.iam_root_user_mfa_enabled
  severity    = "critical"

  tags = merge(local.well_architected_iam_common_tags, {
    category = "well_architected"
  })
}

query "iam_root_user_mfa_enabled" {
  sql = <<-EOQ
    select
      'arn:' || partition || ':::' || account_id as resource,
      case
        when account_mfa_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when account_mfa_enabled then
          'IAM root user in account ' || account_id || ' (global) has MFA enabled.'
        else
          'IAM root user in account ' || account_id || ' (global) does not have MFA enabled.'
      end as reason
      ${local.common_dimensions_global_sql}
    from
      aws_iam_account_summary;
  EOQ
}

control "iam_root_user_hardware_mfa_enabled" {
  title       = "IAM root user hardware MFA should be enabled"
  description = "Manage access to resources in the AWS Cloud by ensuring hardware MFA is enabled for the root user."
  query       = query.iam_root_user_hardware_mfa_enabled
  severity    = "critical"

  tags = merge(local.well_architected_iam_common_tags, {
    category = "well_architected"
  })
}

query "iam_root_user_hardware_mfa_enabled" {
  sql = <<-EOQ
    select
      'arn:' || s.partition || ':::' || s.account_id as resource,
      case
        when s.account_mfa_enabled and d.serial_number is null then 'ok'
        else 'alarm'
      end as status,
      case
        when s.account_mfa_enabled = false then
          'IAM root user in account ' || s.account_id || ' (global) does not have MFA enabled.'
        when d.serial_number is not null then
          'IAM root user in account ' || s.account_id || ' (global) has MFA enabled, but it is a virtual device (hardware MFA required).'
        else
          'IAM root user in account ' || s.account_id || ' (global) has hardware MFA enabled.'
      end as reason
      ${replace(local.common_dimensions_qualifier_global_sql, "__QUALIFIER__", "s.")}
    from
      aws_iam_account_summary as s
      left join aws_iam_virtual_mfa_device as d on (d.user ->> 'Arn') = 'arn:' || s.partition || ':iam::' || s.account_id || ':root';
  EOQ
}

control "iam_root_user_no_access_keys" {
  title       = "IAM root user should not have access keys"
  description = "Access to systems and assets can be controlled by checking that the root user does not have access keys attached to their IAM role."
  query       = query.iam_root_user_no_access_keys
  severity    = "critical"

  tags = merge(local.well_architected_iam_common_tags, {
    category = "well_architected"
  })
}

query "iam_root_user_no_access_keys" {
  sql = <<-EOQ
    select
      'arn:' || partition || ':::' || account_id as resource,
      case
        when account_access_keys_present > 0 then 'alarm'
        else 'ok'
      end as status,
      case
        when account_access_keys_present > 0 then
          'IAM root user in account ' || account_id || ' (global) has access keys configured.'
        else
          'IAM root user in account ' || account_id || ' (global) does not have access keys configured.'
      end as reason
      ${local.common_dimensions_global_sql}
    from
      aws_iam_account_summary;
  EOQ
}
