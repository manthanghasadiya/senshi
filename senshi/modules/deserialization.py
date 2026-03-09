from senshi.modules.base import VulnModule, TestResult
from senshi.reporters.models import Finding, Severity, Confidence


class DeserializationModule(VulnModule):
    name = "deserialization"
    description = "Insecure Deserialization"
    severity = Severity.CRITICAL
    cwe_id = 502
    payloads_dir = "deserialization"
    techniques = ["java_detection", "java_gadgets", "python_pickle", "php", "dotnet"]
    
    # Content-Type indicators
    JAVA_INDICATORS = [
        "application/x-java-serialized-object",
        "application/java-archive",
        "rO0AB",  # Base64-encoded Java serialized object prefix
    ]
    
    PICKLE_INDICATORS = [
        "application/x-python-serialize",
        "gASV",  # Base64-encoded pickle prefix
    ]
    
    def is_applicable(self, endpoint: dict, tech_stack: dict) -> float:
        score = 0.0
        
        # Check Content-Type
        content_type = endpoint.get("content_type", "")
        if any(x in content_type for x in self.JAVA_INDICATORS):
            score += 0.8
        if any(x in content_type for x in self.PICKLE_INDICATORS):
            score += 0.8
        
        # Check tech stack
        frameworks = tech_stack.get("framework", [])
        if isinstance(frameworks, list):
            stack_str = " ".join(frameworks).lower()
        else:
            stack_str = str(frameworks).lower()
            
        if any(fw in stack_str for fw in ["java", "spring", "pickle", "python", "django", "laravel"]):
            score += 0.3
        if "python" in stack_str or "django" in stack_str or "flask" in stack_str:
            score += 0.2
        if "php" in stack_str or "laravel" in stack_str:
            score += 0.2
        
        # Check for common deser endpoints
        url_lower = endpoint.get("url", "").lower()
        if any(x in url_lower for x in ["deserialize", "object", "session", "viewstate"]):
            score += 0.3
        
        # POST with binary/base64 body
        if endpoint.get("method") == "POST":
            score += 0.2
        
        return min(score, 1.0)
    
    def get_injection_points(self, endpoint: dict) -> list[dict]:
        """Body and specific params are injection points."""
        points = [{"location": "body", "name": "request_body"}]
        
        for param in endpoint.get("params", []):
            if any(x in param.lower() for x in ["data", "object", "session", "state", "token"]):
                points.append({"location": "param", "name": param})
        
        return points
    
    def analyze_result(self, result: TestResult) -> Finding | None:
        """Check for deserialization indicators."""
        response = result.response
        
        # Check for Java deserialization errors
        java_errors = [
            "java.io.InvalidClassException",
            "java.io.StreamCorruptedException",
            "ClassNotFoundException",
            "java.lang.ClassCastException",
            "ObjectInputStream",
        ]
        if any(err in response["body"] for err in java_errors):
            return Finding(
                title="Java Deserialization Endpoint Detected",
                severity=Severity.CRITICAL,
                confidence=Confidence.LIKELY,
                category="deserialization",
                description="Endpoint processes serialized Java objects. Test with ysoserial gadget chains.",
                endpoint=result.request["url"],
                payload=result.payload,
                evidence="Java serialization error in response",
            )
        
        # Check for Python pickle errors
        pickle_errors = [
            "unpickling",
            "pickle.UnpicklingError",
            "_pickle.UnpicklingError",
        ]
        if any(err in response["body"] for err in pickle_errors):
            return Finding(
                title="Python Pickle Deserialization Detected",
                severity=Severity.CRITICAL,
                confidence=Confidence.LIKELY,
                category="deserialization",
                description="Endpoint processes pickled Python objects, likely vulnerable to RCE.",
                endpoint=result.request["url"],
                payload=result.payload,
            )
        
        # Check for OOB callback (confirms RCE)
        if result.callback_received:
            return Finding(
                title="Insecure Deserialization — RCE Confirmed",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="deserialization",
                description="Deserialization payload triggered callback, confirming remote code execution.",
                endpoint=result.request["url"],
                payload=result.payload,
                evidence=f"Callback received from target",
            )
        
        return None
