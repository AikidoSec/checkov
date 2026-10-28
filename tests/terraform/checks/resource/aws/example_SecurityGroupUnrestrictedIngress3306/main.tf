# Independent examples of public MySQL ingress and restricted-source controls.
resource "aws_security_group" "public_mysql" {
  name = "public-mysql-fixture"
  ingress {
    protocol    = "tcp"
    from_port   = 3306
    to_port     = 3306
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "restricted_mysql" {
  ingress {
    protocol    = "tcp"
    from_port   = 3306
    to_port     = 3306
    cidr_blocks = ["10.42.0.0/16", "127.0.0.1/32"]
  }
}

resource "aws_security_group" "self_then_public" {
  ingress {
    protocol  = "tcp"
    from_port = 3306
    to_port   = 3306
    self      = true
  }
  ingress {
    protocol         = "tcp"
    from_port        = 3300
    to_port          = 3310
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_security_group" "no_ingress" {
  name = "empty-ingress-fixture"
}

resource "aws_security_group_rule" "public_range" {
  type              = "ingress"
  security_group_id = aws_security_group.no_ingress.id
  protocol          = "6"
  from_port         = 3200
  to_port           = 3400
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "outbound_control" {
  type              = "egress"
  security_group_id = aws_security_group.no_ingress.id
  protocol          = "-1"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_vpc_security_group_ingress_rule" "public_ipv6" {
  security_group_id = aws_security_group.no_ingress.id
  ip_protocol       = "tcp"
  from_port         = 3306
  to_port           = 3306
  cidr_ipv6         = "::/0"
}

resource "aws_vpc_security_group_ingress_rule" "all_protocols" {
  security_group_id = aws_security_group.no_ingress.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "application_source" {
  security_group_id            = aws_security_group.no_ingress.id
  referenced_security_group_id = aws_security_group.restricted_mysql.id
  ip_protocol                 = "tcp"
  from_port                   = 3306
  to_port                     = 3306
}

resource "aws_vpc_security_group_ingress_rule" "web_only" {
  security_group_id = aws_security_group.no_ingress.id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}
