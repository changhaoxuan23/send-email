#!/bin/env python3
"""Send mails."""

from argparse import ArgumentParser
from base64 import b16decode
from email.message import EmailMessage
from mimetypes import guess_type
from pathlib import Path
from smtplib import SMTP_SSL
from sys import stdin

have_secret_storage_accessor = False
try:
  import secret_storage_accessor

  have_secret_storage_accessor = True
except ImportError:
  pass

parser = ArgumentParser()
if have_secret_storage_accessor:
  parser.add_argument("--one-time-key", action="store_true", help="Remove the value from server after query.")
address_parser = parser.add_argument_group(title="email address").add_mutually_exclusive_group(required=True)
address_parser.add_argument(
  "--email",
  help="Specify your email address directly. "
  "This is discouraged since anyone who can list processes with command line can see your email address.",
)
address_parser.add_argument(
  "--email-from-stdin",
  action="store_true",
  help="Read email address from stdin.",
)
if have_secret_storage_accessor:
  address_parser.add_argument(
    "--email-key",
    help="Query email address from secret storage. This should be base16-encoded.",
  )

password_parser = parser.add_argument_group(title="email password").add_mutually_exclusive_group(
  required=True,
)
password_parser.add_argument(
  "--password",
  help="Specify your email password directly. "
  "This is *highly* discouraged since anyone who can list processes with command line can see your "
  "email password. DO NOT use this! Yet I provide this anyway but only for those in a fully trusted "
  "environment and want a simple way to get things done.",
)
password_parser.add_argument(
  "--password-from-stdin",
  action="store_true",
  help="Read email password from stdin.",
)
if have_secret_storage_accessor:
  password_parser.add_argument(
    "--password-key",
    help="Query email password from secret storage. This should be base16-encoded.",
  )

server_parser = parser.add_argument_group(title="email server")
server_parser.add_argument(
  "--server-address",
  type=str,
  help="Address/domain name of the SMTP server",
  required=True,
)
server_parser.add_argument(
  "--server-port",
  type=int,
  help="Port of the SMTP server",
  default=465,
)

content_parser = parser.add_argument_group(title="email content")
content_parser.add_argument(
  "--subject",
  type=str,
  help="Subject of email to send",
  default="Email Notification",
)
content_parser.add_argument(
  "--attachment",
  type=str,
  help="Attach files into the email message",
  nargs="+",
  required=False,
)

config = parser.parse_args()
email_address = None
email_password = None
if config.email is not None:
  print("Warning: using --email is discouraged. See --help for more information")
  email_address = config.email
elif config.email_from_stdin:
  email_address = stdin.readline().strip()
elif have_secret_storage_accessor and config.email_key is not None:
  key = b16decode(config.email_key.encode("utf-8"), casefold=True)
  email_address_viewer = secret_storage_accessor.get_secret(memoryview(key), remove=config.one_time_key)
  email_address = email_address_viewer.tobytes().decode("utf-8")
  secret_storage_accessor.release_secure_string(email_address_viewer)

if config.password is not None:
  print("Warning: using --password is *highly* discouraged! See --help for more information")
  email_password = config.password
elif config.password_from_stdin:
  email_password = stdin.readline().strip()
elif have_secret_storage_accessor and config.password_key is not None:
  key = b16decode(config.password_key.encode("utf-8"), casefold=True)
  email_password_viewer = secret_storage_accessor.get_secret(memoryview(key), remove=config.one_time_key)
  email_password = email_password_viewer.tobytes().decode("utf-8")
  secret_storage_accessor.release_secure_string(email_password_viewer)

message = EmailMessage()
message.preamble = "You possibly need a MIME-aware mail reader to view this message without pain.\n"
message.set_content(stdin.read())

message["Subject"] = config.subject
message["From"] = email_address
message["To"] = email_address

for attachment in config.attachment:
  path = Path(attachment)
  if not path.is_file():
    print(f"Warning: {path} is not a regular file, ignored")
    continue

  mime_type, encoding = guess_type(path)
  if mime_type is None or encoding is not None:
    mime_type = "application/octet-stream"
  main_type, sub_type = mime_type.split("/", 1)
  with path.open("rb") as attachment_file:
    message.add_attachment(attachment_file.read(), maintype=main_type, subtype=sub_type, filename=path.name)


smtp_instance = SMTP_SSL(config.server_address, port=config.server_port)
smtp_instance.login(email_address, email_password)
smtp_instance.send_message(message)
smtp_instance.quit()
