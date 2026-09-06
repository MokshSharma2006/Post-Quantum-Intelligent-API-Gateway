import zmq
import time
import json
import re

from collections import defaultdict

from llm_classifier import LLMThreatClassifier


# ============================================================
# AI SECURITY / ANOMALY ANALYZER
# ============================================================

class SecurityAnalyzer:

    def __init__(self):

        # ----------------------------------------------------
        # Request history
        # ----------------------------------------------------

        self.client_requests = defaultdict(list)

        # ----------------------------------------------------
        # Endpoint history
        # ----------------------------------------------------

        self.client_endpoints = defaultdict(list)

        # ----------------------------------------------------
        # Gemini cooldown
        # ----------------------------------------------------

        self.llm_last_analysis = {}

        self.llm_cooldown_seconds = 10

        # ----------------------------------------------------
        # Analysis window
        # ----------------------------------------------------

        self.window_seconds = 10

        # ----------------------------------------------------
        # Known endpoints
        # ----------------------------------------------------

        self.known_endpoints = {
            "/api/hello",
            "/api/data"
        }

        # ----------------------------------------------------
        # Known HTTP methods
        # ----------------------------------------------------

        self.known_methods = {
            "GET",
            "POST"
        }


    # ========================================================
    # CLEAN OLD REQUESTS
    # ========================================================

    def cleanup_old_requests(
        self,
        client_ip,
        current_time
    ):

        self.client_requests[client_ip] = [
            timestamp
            for timestamp in self.client_requests[client_ip]
            if current_time - timestamp <= self.window_seconds
        ]


    # ========================================================
    # CALCULATE BURST SCORE
    # ========================================================

    def calculate_burst_score(
        self,
        timestamps,
        current_time
    ):

        if not timestamps:
            return 0

        recent_requests = [
            timestamp
            for timestamp in timestamps
            if current_time - timestamp <= 2
        ]

        count = len(recent_requests)

        if count >= 15:
            return 30

        if count >= 10:
            return 20

        if count >= 5:
            return 10

        return 0


    # ========================================================
    # PAYLOAD ANALYSIS
    # ========================================================

    def analyze_payload(
        self,
        request_body
    ):

        if not request_body:

            return {
                "payload_score": 0,
                "payload_indicators": []
            }


        body = str(
            request_body
        )

        # ----------------------------------------------------
        # Limit payload analysis
        # ----------------------------------------------------

        body_to_scan = body[:5000]

        body_lower = body_to_scan.lower()

        score = 0

        indicators = []


        # ====================================================
        # SQL INJECTION DETECTION
        # ====================================================

        sql_patterns = [

            r"\bor\s+1\s*=\s*1",

            r"\band\s+1\s*=\s*1",

            r"\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1",

            r"\bunion\s+select\b",

            r"\bselect\s+.+\s+\bfrom\b",

            r"\bdrop\s+table\b",

            r"\binsert\s+into\b",

            r"\bdelete\s+from\b",

            r"--",

            r"/\*.*\*/",

            r";\s*(select|insert|update|delete|drop)"
        ]

        sql_detected = False

        for pattern in sql_patterns:

            try:

                if re.search(
                    pattern,
                    body_lower,
                    re.IGNORECASE
                ):

                    sql_detected = True
                    break

            except re.error:

                continue


        if sql_detected:

            score += 35

            indicators.append(
                "SQL injection pattern detected"
            )


        # ====================================================
        # COMMAND INJECTION DETECTION
        # ====================================================

        command_patterns = [

            r";\s*(ls|cat|pwd|whoami|id|uname|curl|wget|bash|sh)\b",

            r"\|\s*(ls|cat|pwd|whoami|id|uname|curl|wget|bash|sh)\b",

            r"&&\s*(ls|cat|pwd|whoami|id|uname|curl|wget|bash|sh)\b",

            r"\$\([^)]*\)",

            r"`[^`]+`",

            r"\b(wget|curl)\s+https?://",

            r"\bchmod\s+[0-7]{3,4}\b",

            r"\bchown\s+"
        ]

        command_detected = False

        for pattern in command_patterns:

            try:

                if re.search(
                    pattern,
                    body_lower,
                    re.IGNORECASE
                ):

                    command_detected = True
                    break

            except re.error:

                continue


        if command_detected:

            score += 40

            indicators.append(
                "Command injection pattern detected"
            )


        # ====================================================
        # PATH TRAVERSAL DETECTION
        # ====================================================

        path_patterns = [

            r"\.\./",

            r"\.\.\\",

            r"%2e%2e%2f",

            r"%2e%2e%5c",

            r"\.\.%2f",

            r"\.\.%5c",

            r"/etc/passwd",

            r"\\windows\\system32",

            r"\bboot\.ini\b"
        ]

        path_detected = False

        for pattern in path_patterns:

            try:

                if re.search(
                    pattern,
                    body_lower,
                    re.IGNORECASE
                ):

                    path_detected = True
                    break

            except re.error:

                continue


        if path_detected:

            score += 35

            indicators.append(
                "Path traversal pattern detected"
            )


        # ====================================================
        # AUTHENTICATION ABUSE DETECTION
        # ====================================================

        auth_patterns = [

            r'"username"\s*:\s*"admin"',

            r'"user"\s*:\s*"admin"',

            r'"username"\s*:\s*"root"',

            r'"user"\s*:\s*"root"',

            r'"password"\s*:\s*".{1,}"'
        ]

        auth_detected = False

        for pattern in auth_patterns:

            try:

                if re.search(
                    pattern,
                    body_lower,
                    re.IGNORECASE
                ):

                    auth_detected = True
                    break

            except re.error:

                continue


        if auth_detected:

            score += 10

            indicators.append(
                "Authentication-related payload detected"
            )


        # ====================================================
        # SCRIPT INJECTION DETECTION
        # ====================================================

        script_patterns = [

            r"<script\b",

            r"javascript:",

            r"onerror\s*=",

            r"onload\s*=",

            r"<iframe\b"
        ]

        script_detected = False

        for pattern in script_patterns:

            try:

                if re.search(
                    pattern,
                    body_lower,
                    re.IGNORECASE
                ):

                    script_detected = True
                    break

            except re.error:

                continue


        if script_detected:

            score += 30

            indicators.append(
                "Script injection pattern detected"
            )


        # ====================================================
        # OVERSIZED PAYLOAD
        # ====================================================

        if len(body) > 10000:

            score += 15

            indicators.append(
                "Oversized request payload"
            )


        # ====================================================
        # PAYLOAD SCORE LIMIT
        # ====================================================

        score = min(
            score,
            60
        )


        return {

            "payload_score":
                score,

            "payload_indicators":
                indicators
        }


    # ========================================================
    # GEMINI COOLDOWN
    # ========================================================

    def should_run_llm(
        self,
        client_ip
    ):

        current_time = time.time()

        last_analysis = self.llm_last_analysis.get(
            client_ip,
            0
        )

        if (
            current_time - last_analysis
            >= self.llm_cooldown_seconds
        ):

            self.llm_last_analysis[client_ip] = (
                current_time
            )

            return True

        return False


    # ========================================================
    # ANALYZE REQUEST
    # ========================================================

    def analyze(
        self,
        event
    ):

        client_ip = event.get(
            "client_ip",
            "unknown"
        )

        endpoint = event.get(
            "endpoint",
            "unknown"
        )

        method = event.get(
            "method",
            "unknown"
        )

        request_body = event.get(
            "request_body",
            ""
        )

        current_time = time.time()


        # ====================================================
        # RECORD REQUEST
        # ====================================================

        self.client_requests[client_ip].append(
            current_time
        )

        self.client_endpoints[client_ip].append(
            endpoint
        )


        # ====================================================
        # CLEAN OLD REQUESTS
        # ====================================================

        self.cleanup_old_requests(
            client_ip,
            current_time
        )

        timestamps = self.client_requests[
            client_ip
        ]


        # ====================================================
        # REQUEST COUNT
        # ====================================================

        request_count = len(
            timestamps
        )


        # ====================================================
        # REQUESTS PER SECOND
        # ====================================================

        requests_per_second = (
            request_count /
            self.window_seconds
        )


        # ====================================================
        # BURST SCORE
        # ====================================================

        burst_score = self.calculate_burst_score(
            timestamps,
            current_time
        )


        # ====================================================
        # ENDPOINT VALIDATION
        # ====================================================

        unknown_endpoint = (
            endpoint not in
            self.known_endpoints
        )


        # ====================================================
        # METHOD VALIDATION
        # ====================================================

        unknown_method = (
            method not in
            self.known_methods
        )


        # ====================================================
        # REPEATED ENDPOINT
        # ====================================================

        endpoint_history = self.client_endpoints[
            client_ip
        ]

        recent_endpoints = endpoint_history[-20:]

        repeated_requests = (
            len(recent_endpoints) >= 10
            and
            len(set(recent_endpoints)) == 1
        )


        # ====================================================
        # PAYLOAD ANALYSIS
        # ====================================================

        payload_result = self.analyze_payload(
            request_body
        )

        payload_score = payload_result[
            "payload_score"
        ]

        payload_indicators = payload_result[
            "payload_indicators"
        ]


        # ====================================================
        # BEHAVIORAL SCORE
        # ====================================================

        score = 0

        reasons = []


        # ----------------------------------------------------
        # Request frequency
        # ----------------------------------------------------

        if request_count >= 20:

            score += 30

            reasons.append(
                "Very high request frequency"
            )

        elif request_count >= 10:

            score += 15

            reasons.append(
                "Elevated request frequency"
            )


        # ----------------------------------------------------
        # Requests per second
        # ----------------------------------------------------

        if requests_per_second >= 2:

            score += 15

            reasons.append(
                "High requests per second"
            )


        # ----------------------------------------------------
        # Burst behavior
        # ----------------------------------------------------

        score += burst_score

        if burst_score > 0:

            reasons.append(
                "Burst traffic detected"
            )


        # ----------------------------------------------------
        # Unknown endpoint
        # ----------------------------------------------------

        if unknown_endpoint:

            score += 25

            reasons.append(
                "Unknown API endpoint"
            )


        # ----------------------------------------------------
        # Unknown method
        # ----------------------------------------------------

        if unknown_method:

            score += 15

            reasons.append(
                "Unexpected HTTP method"
            )


        # ----------------------------------------------------
        # Repeated endpoint
        # ----------------------------------------------------

        if repeated_requests:

            score += 10

            reasons.append(
                "Repeated requests to same endpoint"
            )


        # ====================================================
        # ADD PAYLOAD SCORE
        # ====================================================

        score += payload_score


        # ----------------------------------------------------
        # Add payload indicators
        # ----------------------------------------------------

        for indicator in payload_indicators:

            reasons.append(
                indicator
            )


        # ====================================================
        # FINAL SCORE
        # ====================================================

        score = min(
            score,
            100
        )


        # ====================================================
        # THREAT CLASSIFICATION
        #
        # A high-risk payload indicator can directly
        # classify the request as MALICIOUS.
        # ====================================================

        if (
            score >= 70
            or
            payload_score >= 35
        ):

            threat_level = "MALICIOUS"

            action = "BLOCK"

        elif score >= 30:

            threat_level = "SUSPICIOUS"

            action = "MONITOR"

        else:

            threat_level = "NORMAL"

            action = "ALLOW"


        # ====================================================
        # RETURN RESULT
        # ====================================================

        return {

            "client_ip":
                client_ip,

            "endpoint":
                endpoint,

            "method":
                method,

            "request_count":
                request_count,

            "requests_per_second":
                round(
                    requests_per_second,
                    2
                ),

            "burst_score":
                burst_score,

            "payload_score":
                payload_score,

            "payload_indicators":
                payload_indicators,

            "unknown_endpoint":
                unknown_endpoint,

            "unknown_method":
                unknown_method,

            "repeated_requests":
                repeated_requests,

            "anomaly_score":
                score,

            "threat_level":
                threat_level,

            "action":
                action,

            "reasons":
                reasons
        }


# ============================================================
# REQUEST BODY SANITIZATION
# ============================================================

def sanitize_request_body(
    request_body
):

    if not request_body:

        return ""


    # --------------------------------------------------------
    # Limit body sent to AI
    # --------------------------------------------------------

    request_body = str(
        request_body
    )[:2000]


    # --------------------------------------------------------
    # Try JSON parsing
    # --------------------------------------------------------

    try:

        data = json.loads(
            request_body
        )

        if isinstance(
            data,
            dict
        ):

            sensitive_fields = {

                "password",
                "passwd",
                "secret",
                "token",
                "api_key",
                "apikey",
                "authorization",
                "access_token",
                "refresh_token",
                "cookie"
            }


            # ------------------------------------------------
            # Redact sensitive values
            # ------------------------------------------------

            for field in sensitive_fields:

                if field in data:

                    data[field] = (
                        "[REDACTED]"
                    )


            return json.dumps(
                data
            )

    except Exception:

        pass


    return request_body


# ============================================================
# MAIN
# ============================================================

def main():

    # ========================================================
    # ZERO MQ CONTEXT
    # ========================================================

    context = zmq.Context()


    # ========================================================
    # GATEWAY -> AI
    # ========================================================

    socket = context.socket(
        zmq.PULL
    )

    socket.bind(
        "tcp://127.0.0.1:5555"
    )


    # ========================================================
    # AI -> GATEWAY
    # ========================================================

    decision_socket = context.socket(
        zmq.PUSH
    )

    decision_socket.connect(
        "tcp://127.0.0.1:5556"
    )


    # ========================================================
    # SECURITY ANALYZER
    # ========================================================

    analyzer = SecurityAnalyzer()


    # ========================================================
    # GEMINI CLASSIFIER
    # ========================================================

    llm_classifier = (
        LLMThreatClassifier()
    )


    # ========================================================
    # STARTUP
    # ========================================================

    print(
        "====================================="
    )

    print(
        " AI Security Engine"
    )

    print(
        "====================================="
    )

    print(
        " ZeroMQ Input  : tcp://127.0.0.1:5555"
    )

    print(
        " ZeroMQ Output : tcp://127.0.0.1:5556"
    )

    print(
        " Mode          : ANOMALY + PAYLOAD + LLM"
    )

    print(
        " Enforcement   : ENABLED"
    )

    print(
        " LLM Provider  : Google Gemini"
    )

    print(
        " LLM Cooldown  : 10 seconds/client"
    )

    print(
        " Payload Scan  : ENABLED"
    )

    print(
        " Sensitive Data: REDACTED"
    )

    print(
        " Status        : ACTIVE"
    )

    print(
        "====================================="
    )


    # ========================================================
    # EVENT LOOP
    # ========================================================

    while True:

        try:

            # =================================================
            # RECEIVE EVENT
            # =================================================

            event = socket.recv_json()


            print(
                "\n-------------------------------------"
            )

            print(
                "[EVENT RECEIVED]"
            )

            print(
                event
            )


            # =================================================
            # ANALYZE EVENT
            # =================================================

            result = analyzer.analyze(
                event
            )


            # =================================================
            # FEATURE EXTRACTION
            # =================================================

            print(
                "\n[FEATURE EXTRACTION]"
            )

            print(
                f"Request Count     : "
                f"{result['request_count']}"
            )

            print(
                f"Requests/sec      : "
                f"{result['requests_per_second']}"
            )

            print(
                f"Burst Score       : "
                f"{result['burst_score']}"
            )

            print(
                f"Payload Score     : "
                f"{result['payload_score']}"
            )

            print(
                f"Unknown Endpoint  : "
                f"{result['unknown_endpoint']}"
            )

            print(
                f"Unknown Method    : "
                f"{result['unknown_method']}"
            )

            print(
                f"Repeated Requests : "
                f"{result['repeated_requests']}"
            )


            # =================================================
            # PAYLOAD INDICATORS
            # =================================================

            if result[
                "payload_indicators"
            ]:

                print(
                    "Payload Indicators: "
                    + ", ".join(
                        result[
                            "payload_indicators"
                        ]
                    )
                )

            else:

                print(
                    "Payload Indicators: None"
                )


            # =================================================
            # SECURITY DECISION
            # =================================================

            print(
                "\n[SECURITY DECISION]"
            )

            print(
                f"Anomaly Score     : "
                f"{result['anomaly_score']}/100"
            )

            print(
                f"Threat Level      : "
                f"{result['threat_level']}"
            )

            print(
                f"Action            : "
                f"{result['action']}"
            )


            # =================================================
            # REASONS
            # =================================================

            if result[
                "reasons"
            ]:

                print(
                    "Reasons           : "
                    + ", ".join(
                        result[
                            "reasons"
                        ]
                    )
                )

            else:

                print(
                    "Reasons           : None"
                )


            # =================================================
            # DEFAULT LLM RESULT
            # =================================================

            llm_result = {

                "enabled":
                    False,

                "provider":
                    "gemini",

                "attack_type":
                    "NOT_ANALYZED",

                "severity":
                    "NONE",

                "confidence":
                    0,

                "recommendation":
                    "NONE",

                "explanation":
                    "LLM analysis not required"
            }


            # =================================================
            # GEMINI ANALYSIS
            # =================================================

            if result[
                "threat_level"
            ] in {
                "SUSPICIOUS",
                "MALICIOUS"
            }:

                print(
                    "\n[LLM ANALYSIS]"
                )


                # ------------------------------------------------
                # Gemini cooldown
                # ------------------------------------------------

                if analyzer.should_run_llm(
                    result["client_ip"]
                ):

                    print(
                        "Gemini analysis started..."
                    )


                    # ------------------------------------------------
                    # Extract request body
                    # ------------------------------------------------

                    request_body = event.get(
                        "request_body",
                        ""
                    )


                    # ------------------------------------------------
                    # Sanitize request body
                    # ------------------------------------------------

                    request_body = (
                        sanitize_request_body(
                            request_body
                        )
                    )


                    try:

                        # ========================================
                        # GEMINI ANALYSIS
                        # ========================================

                        llm_result = (
                            llm_classifier.analyze(

                                endpoint=
                                    result[
                                        "endpoint"
                                    ],

                                method=
                                    result[
                                        "method"
                                    ],

                                client_ip=
                                    result[
                                        "client_ip"
                                    ],

                                anomaly_score=
                                    result[
                                        "anomaly_score"
                                    ],

                                threat_level=
                                    result[
                                        "threat_level"
                                    ],

                                request_body=
                                    request_body
                            )
                        )


                        # ========================================
                        # DISPLAY GEMINI RESULT
                        # ========================================

                        print(
                            f"Provider          : "
                            f"{llm_result.get(
                                'provider',
                                'gemini'
                            )}"
                        )

                        print(
                            f"Attack Type       : "
                            f"{llm_result.get(
                                'attack_type',
                                'UNKNOWN'
                            )}"
                        )

                        print(
                            f"Severity          : "
                            f"{llm_result.get(
                                'severity',
                                'UNKNOWN'
                            )}"
                        )

                        print(
                            f"Confidence        : "
                            f"{llm_result.get(
                                'confidence',
                                0
                            )}%"
                        )

                        print(
                            f"Recommendation    : "
                            f"{llm_result.get(
                                'recommendation',
                                'MONITOR'
                            )}"
                        )

                        print(
                            f"Explanation       : "
                            f"{llm_result.get(
                                'explanation',
                                ''
                            )}"
                        )


                    except Exception as llm_error:

                        print(
                            f"[LLM ERROR] "
                            f"{llm_error}"
                        )


                        llm_result = {

                            "enabled":
                                True,

                            "provider":
                                "gemini",

                            "attack_type":
                                "UNKNOWN",

                            "severity":
                                "UNKNOWN",

                            "confidence":
                                0,

                            "recommendation":
                                "MONITOR",

                            "explanation":
                                "LLM analysis failed"
                        }


                else:

                    print(
                        "Skipped - Gemini cooldown active"
                    )


            else:

                print(
                    "\n[LLM ANALYSIS]"
                )

                print(
                    "Skipped - NORMAL traffic"
                )


            # =================================================
            # ENFORCEMENT AUTHORITY
            # =================================================
            #
            # IMPORTANT:
            #
            # The deterministic security engine controls
            # ALLOW / MONITOR / BLOCK.
            #
            # Gemini provides intelligence and classification
            # but does not directly override the gateway.
            #
            # =================================================

            final_action = (
                result["action"]
            )


            # =================================================
            # BUILD FINAL DECISION
            # =================================================

            decision = {

                "client_ip":
                    result["client_ip"],

                "action":
                    final_action,

                "threat_level":
                    result["threat_level"],

                "threat_score":
                    result["anomaly_score"],

                "duration_seconds":
                    30,

                # --------------------------------------------
                # LLM information
                # --------------------------------------------

                "llm_enabled":
                    llm_result.get(
                        "enabled",
                        False
                    ),

                "llm_provider":
                    llm_result.get(
                        "provider",
                        "gemini"
                    ),

                "attack_type":
                    llm_result.get(
                        "attack_type",
                        "UNKNOWN"
                    ),

                "severity":
                    llm_result.get(
                        "severity",
                        "NONE"
                    ),

                "confidence":
                    llm_result.get(
                        "confidence",
                        0
                    ),

                "recommendation":
                    llm_result.get(
                        "recommendation",
                        "NONE"
                    ),

                "explanation":
                    llm_result.get(
                        "explanation",
                        ""
                    ),

                # --------------------------------------------
                # Payload information
                # --------------------------------------------

                "payload_score":
                    result[
                        "payload_score"
                    ],

                "payload_indicators":
                    result[
                        "payload_indicators"
                    ]
            }


            # =================================================
            # SEND DECISION TO C++ GATEWAY
            # =================================================

            decision_socket.send_json(
                decision
            )


            print(
                "\n[AI DECISION SENT TO GATEWAY]"
            )

            print(
                decision
            )


        # ====================================================
        # KEYBOARD INTERRUPT
        # ====================================================

        except KeyboardInterrupt:

            print(
                "\n[INFO] Security engine stopped."
            )

            break


        # ====================================================
        # GENERAL ERROR
        # ====================================================

        except Exception as error:

            print(
                f"[ERROR] {error}"
            )


    # ========================================================
    # CLEANUP
    # ========================================================

    socket.close()

    decision_socket.close()

    context.term()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()