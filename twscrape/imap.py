import asyncio
import email as emaillib
import imaplib
import os
import time
from datetime import datetime
import re
from dataclasses import dataclass
from email import message 

from .logger import logger

TWS_WAIT_EMAIL_CODE = [os.getenv("TWS_WAIT_EMAIL_CODE"), os.getenv("LOGIN_CODE_TIMEOUT"), 30]
TWS_WAIT_EMAIL_CODE = [int(x) for x in TWS_WAIT_EMAIL_CODE if x is not None][0]


class EmailLoginError(Exception):
    def __init__(self, message="Email login error"):
        self.message = message
        super().__init__(self.message)


class EmailCodeTimeoutError(Exception):
    def __init__(self, message="Email code timeout"):
        self.message = message
        super().__init__(self.message)


IMAP_MAPPING: dict[str, str] = {
    "yahoo.com": "imap.mail.yahoo.com",
    "icloud.com": "imap.mail.me.com",
    "outlook.com": "imap-mail.outlook.com",
    "hotmail.com": "imap-mail.outlook.com",
    "proton.me": "127.0.0.1:1143",
}

@dataclass 
class EmailCodeResult:
    code: str
    username: str | None

    def __init__(self, code: str, username: str | None):
        self.code = code
        self.username = username

    def __str__(self):
        return f"EmailCodeResult(code={self.code}, username={self.username})"

    def __repr__(self):
        return str(self)


def add_imap_mapping(email_domain: str, imap_domain: str):
    IMAP_MAPPING[email_domain] = imap_domain


def _get_imap_domain(email: str) -> str:
    email_domain = email.split("@")[1]
    if email_domain in IMAP_MAPPING:
        return IMAP_MAPPING[email_domain]
    return f"imap.{email_domain}"


def _wait_email_code(imap: imaplib.IMAP4, count: int, min_t: datetime | None) -> EmailCodeResult | None:
    for i in range(count, 0, -1):
        _, rep = imap.fetch(str(i), "(RFC822)")
        for x in rep:
            if isinstance(x, tuple):
                msg = emaillib.message_from_bytes(x[1])

                # https://www.ietf.org/rfc/rfc9051.html#section-6.3.12-13
                msg_time = msg.get("Date", "").split("(")[0].strip()
                msg_time = datetime.strptime(msg_time, "%a, %d %b %Y %H:%M:%S %z")

                msg_from = str(msg.get("From", "")).lower()
                msg_subj = str(msg.get("Subject", "")).lower()
                logger.info(f"({i} of {count}) {msg_from} - {msg_time} - {msg_subj}")

                if min_t is not None and msg_time < min_t:
                    return None

                if "info@x.com" in msg_from and "confirmation code is" in msg_subj:
                    # eg. Your X confirmation code is XXX
                    username = _extract_username(msg)
                    code = msg_subj.split(" ")[-1].strip()

                    logger.debug(f"Email code found: {code}")

                    return EmailCodeResult(code, username)

    return None


def _extract_username(msg: message.Message) -> str | None:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))

            # look for plain text parts, but skip attachments
            if ctype == 'text/plain' and 'attachment' not in cdispo:
                body = part.get_payload(decode=True)  # decode
                body = body.decode()
    else:
        # not multipart - i.e. plain text, no attachments
        body = msg.get_payload(decode=True)
        body = body.decode()

    # Extract username from the body
    # Looking for a "We noticed an attempt to log in to your account @VanVanclaud that seems suspicious. Was this you?
    username_match = re.search(r"to log in to your account @(\w+)", body)
    
    if username_match:
        username_found = username_match.group(1)
        logger.debug(f"Username found in email: {username_found}")
        return username_found
    
    return None


async def imap_get_email_code(
    imap: imaplib.IMAP4, email: str, min_t: datetime | None = None
) -> EmailCodeResult:
    try:
        logger.info(f"Waiting for confirmation code for {email}...")
        start_time = time.time()
        while True:
            _, rep = imap.select("INBOX")
            msg_count = int(rep[0].decode("utf-8")) if len(rep) > 0 and rep[0] is not None else 0
            code_result = _wait_email_code(imap, msg_count, min_t)
            if code_result is not None:
                return code_result

            if TWS_WAIT_EMAIL_CODE < time.time() - start_time:
                raise EmailCodeTimeoutError(f"Email code timeout ({TWS_WAIT_EMAIL_CODE} sec)")

            await asyncio.sleep(5)
    except Exception as e:
        imap.select("INBOX")
        imap.close()
        raise e


async def imap_login(email: str, password: str):
    domain = _get_imap_domain(email)

    if ":" in domain:
        host, port = domain.split(":")
        imap = imaplib.IMAP4(host, port)
    else:
        imap = imaplib.IMAP4_SSL(domain)

    try:
        imap.login(email, password)
        imap.select("INBOX", readonly=True)
    except imaplib.IMAP4.error as e:
        logger.error(f"Error logging into {email} on {domain}: {e}")
        raise EmailLoginError() from e

    return imap
