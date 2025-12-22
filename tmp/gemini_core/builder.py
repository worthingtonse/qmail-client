# gemini_core/builder.py
# Handles the building of email content and encoding of attachments.

import logging
from typing import List, Dict, Any, Tuple
from .types import ErrorCode, Email

def build_email_from_parts(text: str, recipients: List[str], subject: str, attachments: List[Dict]) -> Tuple[ErrorCode, Email]:
    """
    Compiles text and attachment data into a structured Email object.

    Args:
        text: The body of the email.
        recipients: A list of recipient email addresses.
        subject: The subject line of the email.
        attachments: A list of dictionaries, where each represents an attachment
                     (e.g., {'filename': 'doc.txt', 'data': b'...'}).

    Returns:
        A tuple of (ErrorCode, Email object).
    """
    try:
        logging.info(f"Building email with subject: '{subject}'")
        
        # In a real implementation, this is where you would handle MIME types,
        # multipart messages, and CBDF encoding for files.
        
        encoded_attachments = []
        for att in attachments:
            encoded_data = _encode_to_cbdf(att['data'])
            encoded_attachments.append(encoded_data)
            logging.info(f"Encoded attachment '{att['filename']}' to CBDF.")

        email = Email(
            subject=subject,
            sender="localuser@qmail.dev", # This would come from config
            recipients=recipients,
            body=text,
            attachments=encoded_attachments
        )
        
        return ErrorCode.SUCCESS, email
        
    except Exception as e:
        logging.error(f"Failed to build email: {e}")
        return ErrorCode.FAILURE, None

def _encode_to_cbdf(data: bytes) -> bytes:
    """
    (Stub) Encodes file data using Compact Binary Document Format.
    """
    # This is a placeholder for a real binary format encoder.
    return b'cbdf_encoded_' + data
