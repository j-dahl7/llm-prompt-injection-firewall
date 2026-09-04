"""
LLM Prompt Injection Firewall

Demonstrates first-pass prompt screening. This lab does not invoke or forward
to an LLM backend.

Detection Categories:
1. Instruction Override - "ignore previous instructions", "disregard above"
2. Jailbreak Attempts - "DAN", "developer mode", "no restrictions"
3. Role Manipulation - "you are now", "pretend to be", "act as"
4. System Prompt Extraction - "show system prompt", "reveal instructions"
5. Encoding Attacks - Base64 encoded malicious payloads
6. PII Patterns - SSN, credit cards, email, phone, IPv4-looking input (no LLM call)
7. Excessive Length - Prompt length attacks

Author: Nine Lives Zero Trust
License: MIT
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Tuple, Optional, Dict, Any

import boto3

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# DynamoDB for attack logging
dynamodb = boto3.resource('dynamodb')
attack_table = dynamodb.Table(os.environ.get('ATTACK_LOG_TABLE', 'llm-firewall-attacks'))

# Configuration
BLOCK_MODE = os.environ.get('BLOCK_MODE', 'true').lower() == 'true'
MAX_PROMPT_LENGTH = int(os.environ.get('MAX_PROMPT_LENGTH', '4000'))
ENABLE_PII_CHECK = os.environ.get('ENABLE_PII_CHECK', 'true').lower() == 'true'
API_SHARED_SECRET = os.environ.get('API_SHARED_SECRET', '')


def _unauthorized_response(message: str, status_code: int = 401) -> Dict[str, Any]:
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({'error': message})
    }


def is_authorized(event: Dict[str, Any]) -> bool:
    if not isinstance(API_SHARED_SECRET, str) or not API_SHARED_SECRET:
        return False

    raw_headers = event.get('headers')
    if not isinstance(raw_headers, dict):
        return False
    headers = {str(k).lower(): v for k, v in raw_headers.items()}
    api_key = headers.get('x-api-key')

    if not isinstance(api_key, str):
        return False
    try:
        # compare_digest only accepts ASCII str values. UTF-8 bytes preserve
        # exact key identity (no normalization), including supported Unicode.
        return hmac.compare_digest(api_key.encode('utf-8'), API_SHARED_SECRET.encode('utf-8'))
    except UnicodeEncodeError:
        # Malformed Unicode must be an ordinary rejection, never a logged key.
        return False


# =============================================================================
# Detection Patterns
# =============================================================================

INJECTION_PATTERNS = {
    'instruction_override': [
        r'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|guidelines?)',
        r'disregard\s+(all\s+)?(previous|prior|above|earlier)',
        r'forget\s+(everything|all|what)\s+(you|i)\s+(said|told|wrote)',
        r'do\s+not\s+follow\s+(the\s+)?(previous|prior|above)',
        r'override\s+(previous|system|all)',
        r'new\s+instructions?\s*[:=]',
    ],
    'jailbreak': [
        r'\bDAN\b',  # "Do Anything Now" jailbreak
        r'developer\s+mode',
        r'god\s+mode',
        r'sudo\s+mode',
        r'no\s+(restrictions?|limitations?|rules?|filters?)',
        r'bypass\s+(filter|safety|restriction|content)',
        r'jailbreak',
        r'unlock\s+(full|all)\s+(capabilities?|potential)',
        r'remove\s+(all\s+)?(restrictions?|limitations?|filters?)',
    ],
    'role_manipulation': [
        r'you\s+are\s+now\s+(?!going|about)',  # "you are now X" but not "you are now going to"
        r'pretend\s+(to\s+be|you\s+are)',
        r'act\s+as\s+(if\s+you\s+are|a)',
        r'roleplay\s+as',
        r'simulate\s+being',
        r'from\s+now\s+on\s+you\s+are',
        r'switch\s+(to|into)\s+.{0,20}\s+mode',
    ],
    'system_prompt_extraction': [
        r'(show|display|reveal|print|output|tell\s+me)\s+(your\s+)?(system\s+prompt|instructions?|rules?|guidelines?)',
        r'what\s+(are|is)\s+your\s+(system\s+prompt|instructions?|initial\s+prompt)',
        r'repeat\s+(your\s+)?(initial|system|original)\s+(prompt|instructions?)',
        r'echo\s+(back\s+)?(your\s+)?(system|initial)',
        r'verbatim\s+(system|initial)',
    ],
    'encoding_bypass': [
        r'base64\s*[:\-]',
        r'decode\s+(this|the\s+following)',
        r'rot13',
        r'hex\s*[:\-]',
        r'interpret\s+(as|the\s+following\s+as)',
    ],
}

PII_PATTERNS = {
    'ssn': r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
    'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    'phone': r'\b(?:\+1[-\s]?)?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}\b',
    'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
}


# =============================================================================
# Detection Functions
# =============================================================================

def check_injection_patterns(prompt: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Check prompt against known injection patterns.

    Returns:
        (is_malicious, attack_type, matched_pattern)
    """
    prompt_lower = prompt.lower()

    for attack_type, patterns in INJECTION_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, prompt_lower, re.IGNORECASE):
                return True, attack_type, pattern

    return False, None, None


def check_pii(prompt: str) -> Tuple[bool, Optional[str]]:
    """
    Check for PII in the prompt that shouldn't be sent to an LLM.

    Returns:
        (has_pii, pii_type)
    """
    if not ENABLE_PII_CHECK:
        return False, None

    for pii_type, pattern in PII_PATTERNS.items():
        match = re.search(pattern, prompt)
        if match:
            return True, pii_type

    return False, None


def check_length(prompt: str) -> Tuple[bool, int]:
    """
    Check if prompt exceeds maximum allowed length.

    Returns:
        (is_too_long, actual_length)
    """
    return len(prompt) > MAX_PROMPT_LENGTH, len(prompt)


def check_base64_payload(prompt: str) -> Tuple[bool, Optional[int]]:
    """
    Check for base64 encoded malicious payloads.

    Returns:
        (has_encoded_injection, decoded_content_length)
    """
    # Look for base64-like strings (at least 50 chars to avoid JWT/ID false positives)
    b64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
    matches = re.findall(b64_pattern, prompt)

    for match in matches:
        try:
            decoded = base64.b64decode(match, validate=True).decode('utf-8', errors='ignore')
            # Check if decoded content contains injection patterns
            is_malicious, _, _ = check_injection_patterns(decoded)
            if is_malicious:
                # Keep attacker-controlled content out of logs and DynamoDB.
                return True, len(decoded)
        except Exception:
            continue

    return False, None


def analyze_prompt(prompt: str) -> Dict[str, Any]:
    """
    Comprehensive prompt analysis.

    Returns dict with:
        - blocked: bool
        - attack_type: str or None
        - reason: str
        - details: dict with additional info
    """
    result = {
        'blocked': False,
        'attack_type': None,
        'reason': 'Prompt passed all checks',
        'details': {}
    }

    # Check 1: Length
    is_too_long, length = check_length(prompt)
    if is_too_long:
        result['blocked'] = True
        result['attack_type'] = 'excessive_length'
        result['reason'] = f'Prompt exceeds maximum length ({length} > {MAX_PROMPT_LENGTH})'
        result['details']['length'] = length
        return result

    # Check 2: Injection patterns
    is_injection, attack_type, pattern = check_injection_patterns(prompt)
    if is_injection:
        result['blocked'] = True
        result['attack_type'] = attack_type
        result['reason'] = f'Detected {attack_type} pattern'
        result['details']['matched_pattern'] = pattern
        return result

    # Check 3: Base64 encoded payloads
    has_encoded, decoded_length = check_base64_payload(prompt)
    if has_encoded:
        result['blocked'] = True
        result['attack_type'] = 'encoded_injection'
        result['reason'] = 'Detected encoded malicious payload'
        result['details']['decoded_length'] = decoded_length
        return result

    # Check 4: PII
    has_pii, pii_type = check_pii(prompt)
    if has_pii:
        result['blocked'] = True
        result['attack_type'] = f'pii_{pii_type}'
        result['reason'] = f'Detected {pii_type} in prompt'
        return result

    return result


# =============================================================================
# Attack Logging
# =============================================================================

def log_attack(attack_id: str, analysis: Dict[str, Any], source_ip: str, prompt_hash: str):
    """Log blocked attack to DynamoDB for analysis."""
    try:
        attack_table.put_item(Item={
            'attack_id': attack_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'attack_type': analysis['attack_type'],
            'reason': analysis['reason'],
            'source_ip': source_ip,
            'prompt_hash': prompt_hash,  # Hash only, never store actual prompts
            'details': analysis['details'],
        })
    except Exception as e:
        logger.error(f"Failed to log attack: {e}")


# =============================================================================
# Lambda Handler
# =============================================================================

def handler(event, context):
    """
    Main Lambda handler for prompt injection firewall.

    Expects POST with JSON body: {"prompt": "user prompt here"}

    Returns:
        - 200 with a bounded allow decision and mock response if clean
        - 403 with block reason if malicious
    """
    request_id = context.aws_request_id if context else str(uuid.uuid4())

    if not isinstance(event, dict):
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'Invalid request event'})
        }

    if not API_SHARED_SECRET:
        logger.error('API_SHARED_SECRET is not configured')
        return _unauthorized_response('Firewall API is not configured securely', 500)

    if not is_authorized(event):
        return _unauthorized_response('Missing or invalid API key')

    # Parse request
    try:
        body = json.loads(event.get('body', '{}'))
    except (json.JSONDecodeError, TypeError):
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'Invalid JSON body'})
        }

    if not isinstance(body, dict):
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'JSON body must be an object'})
        }

    prompt = body.get('prompt', '')

    if not isinstance(prompt, str) or not prompt.strip():
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'prompt must be a non-empty string'})
        }

    # Get source IP for logging
    request_context = event.get('requestContext')
    request_context = request_context if isinstance(request_context, dict) else {}
    http_context = request_context.get('http')
    http_context = http_context if isinstance(http_context, dict) else {}
    source_ip = str(http_context.get('sourceIp', 'unknown'))[:64]

    # Analyze prompt
    analysis = analyze_prompt(prompt)

    # Create a keyed fingerprint for correlation without storing raw prompts or
    # a plain hash that is easy to precompute for low-entropy input.
    prompt_hash = hmac.new(
        API_SHARED_SECRET.encode('utf-8'),
        prompt.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()[:16]

    # Lambda's JSON logging configuration promotes these `extra` fields to the
    # top-level log object, where CloudWatch metric filters can address them.
    log_entry = {
        'request_id': request_id,
        'blocked': analysis['blocked'],
        'attack_type': analysis['attack_type'],
        'reason': analysis['reason'],
        'source_ip': source_ip,
        'prompt_length': len(prompt),
    }
    logger.info('prompt_screening_result', extra=log_entry)

    if analysis['blocked']:
        # Log attack to DynamoDB
        log_attack(request_id, analysis, source_ip, prompt_hash)
        if BLOCK_MODE:
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'error': 'Prompt blocked by security filter',
                    'reason': analysis['reason'],
                    'attack_type': analysis['attack_type'],
                    'request_id': request_id,
                })
            }
        else:
            # Detection-only mode - log but allow through
            logger.warning(f"DETECTION ONLY - Would have blocked: {analysis['attack_type']}")

    # This lab returns a bounded decision; it does not forward the prompt.
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({
            'status': 'allowed',
            'message': 'Prompt passed security checks',
            'request_id': request_id,
            'mock_response': 'No model was invoked. Integrate a separately secured model service only after independent authorization.',
        })
    }
