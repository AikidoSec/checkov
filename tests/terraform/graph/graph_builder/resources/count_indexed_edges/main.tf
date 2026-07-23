# Boolean count + bucket_prefix (customer test8 pattern)
resource "aws_s3_bucket" "replay" {
  count = var.create_replay_bucket ? 1 : 0

  bucket_prefix = lower("checkov-replay-")
}

resource "aws_s3_bucket_public_access_block" "replay" {
  count = var.create_replay_bucket ? 1 : 0

  bucket = aws_s3_bucket.replay[0].id

  block_public_acls   = true
  block_public_policy = true
}

# Boolean count using != false ternary
resource "aws_s3_bucket" "ne_false" {
  count = var.create_replay_bucket != false ? 1 : 0

  bucket = "checkov-ne-false-bucket"
}

resource "aws_s3_bucket_public_access_block" "ne_false" {
  count = var.create_replay_bucket != false ? 1 : 0

  bucket = aws_s3_bucket.ne_false[0].id

  block_public_acls   = true
  block_public_policy = true
}

# count.index pairing across two instances
resource "aws_s3_bucket" "multi" {
  count = var.replica_count

  bucket = "checkov-multi-${count.index}"
}

resource "aws_s3_bucket_public_access_block" "multi" {
  count = var.replica_count

  bucket = aws_s3_bucket.multi[count.index].id

  block_public_acls   = true
  block_public_policy = true
}

# No count on bucket; dependent still references [0] — stripped-name fallback
resource "aws_s3_bucket" "static" {
  bucket = "checkov-static-bucket"
}

resource "aws_s3_bucket_public_access_block" "static" {
  count = var.enable_static ? 1 : 0

  bucket = aws_s3_bucket.static[0].id

  block_public_acls   = true
  block_public_policy = true
}

# Interpolation wrapper around indexed reference
resource "aws_s3_bucket" "interp" {
  count = var.create_replay_bucket ? 1 : 0

  bucket = "checkov-interp-bucket"
}

resource "aws_s3_bucket_public_access_block" "interp" {
  count = var.create_replay_bucket ? 1 : 0

  bucket = "${aws_s3_bucket.interp[0].id}"

  block_public_acls   = true
  block_public_policy = true
}

# Versioning graph check (CKV_AWS_21) with boolean count
resource "aws_s3_bucket" "versioned" {
  count = var.create_replay_bucket ? 1 : 0

  bucket_prefix = lower("checkov-versioned-")
}

resource "aws_s3_bucket_versioning" "versioned" {
  count = var.create_replay_bucket ? 1 : 0

  bucket = aws_s3_bucket.versioned[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "versioned" {
  count = var.create_replay_bucket ? 1 : 0

  bucket = aws_s3_bucket.versioned[0].id

  block_public_acls   = true
  block_public_policy = true
}
