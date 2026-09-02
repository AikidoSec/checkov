data "aws_iam_policy_document" "fail" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    actions = [
      "s3:Describe*",
    ]
    resources = [
      "*",
    ]
  }
}

data "aws_iam_policy_document" "pass2" {
  version = "2012-10-17"

  statement {
    effect = "Deny"
    actions = [
      "s3:Describe*",
    ]
    resources = [
      "*",
    ]
  }
}

data "aws_iam_policy_document" "pass" {
  statement {
    sid = "1"

    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
    ]

    resources = [
      "arn:aws:s3:::*",
    ]
  }

  statement {
    actions = [
      "s3:ListBucket",
    ]

    resources = [
      "arn:aws:s3:::${var.s3_bucket_name}",
    ]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"

      values = [
        "",
        "home/",
        "home/&{aws:username}/",
      ]
    }
  }

  statement {
    actions = [
      "s3:*",
    ]

    resources = [
      "arn:aws:s3:::${var.s3_bucket_name}/home/&{aws:username}",
      "arn:aws:s3:::${var.s3_bucket_name}/home/&{aws:username}/*",
    ]
  }
}

data "aws_iam_policy_document" "pass_unrestrictable" {
  version = "2012-10-17"

  statement {
    effect = "Allow"
    actions = [
      "s3:ListAllMyBuckets",
    ]
    resources = [
      "*",
    ]
  }
}

data "aws_iam_policy_document" "pass_kms_key_policy" {
  statement {
    sid    = "AllowAccountAdministration"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }

    actions = [
      "kms:*",
    ]
    resources = [
      "*",
    ]
  }
}

resource "aws_kms_key" "pass_kms_key_policy" {
  policy = data.aws_iam_policy_document.pass_kms_key_policy.json
}

data "aws_iam_policy_document" "pass_kms_replica_key_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }

    actions   = ["kms:Sign"]
    resources = ["*"]
  }
}

resource "aws_kms_replica_key" "pass_kms_replica_key_policy" {
  primary_key_arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
  policy          = data.aws_iam_policy_document.pass_kms_replica_key_policy.json
}

data "aws_iam_policy_document" "pass_kms_key_policy_resource" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }

    actions   = ["kms:Sign"]
    resources = ["*"]
  }

  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/scanner"]
    }

    actions   = ["kms:Sign", "kms:GetPublicKey"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "key_policy_resource" {
}

resource "aws_kms_key_policy" "pass_kms_key_policy_resource" {
  key_id = aws_kms_key.key_policy_resource.id
  policy = data.aws_iam_policy_document.pass_kms_key_policy_resource.json
}

data "aws_iam_policy_document" "fail_kms_without_principals" {
  statement {
    actions   = ["kms:Sign"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "fail_kms_without_principals" {
  policy = data.aws_iam_policy_document.fail_kms_without_principals.json
}

resource "aws_iam_policy" "fail_kms_without_principals" {
  policy = data.aws_iam_policy_document.fail_kms_without_principals.json
}

data "aws_iam_policy_document" "fail_non_kms_resource_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }

    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

resource "aws_s3_bucket_policy" "fail_non_kms_resource_policy" {
  bucket = "example"
  policy = data.aws_iam_policy_document.fail_non_kms_resource_policy.json
}

data "aws_iam_policy_document" "fail_kms_mixed_actions" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }

    actions   = ["kms:Sign"]
    resources = ["*"]
  }

  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }

    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "pass_kms_not_principals" {
  statement {
    sid    = "DenyOthers"
    effect = "Deny"

    not_principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "pass_kms_case_insensitive" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }

    actions   = ["KMS:*", "Kms:Decrypt"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "fail_kms_not_actions" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }

    not_actions = ["kms:DisableKey", "kms:ScheduleKeyDeletion"]
    resources   = ["*"]
  }
}

data "aws_iam_policy_document" "fail_kms_global_wildcard" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }

    actions   = ["*"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "pass_condition" {
  statement {
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt"
    ]
    resources = [
      "*"
    ]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [
        "arn"
      ]
    }
  }
}
