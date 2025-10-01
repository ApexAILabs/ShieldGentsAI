"""MCP Server Builder Demo.

Demonstrates how to build secure-by-default MCP servers using ShieldGents.

All security features are automatic:
- Request/response validation
- PII redaction
- Rate limiting
- Exfiltration detection
- Tool sandboxing
- Audit logging
"""

from shieldgents.mcp_server_builder import create_shielded_mcp_server, tool


# Example 1: Simple server with automatic security
def demo_simple_server():
    """Create a simple server with default security."""
    print("\n" + "="*70)
    print("1. SIMPLE SHIELDED MCP SERVER")
    print("="*70)

    # Define tools
    def search(query: str) -> str:
        """Search for information."""
        return f"Search results for: {query}"

    def calculator(expression: str) -> float:
        """Calculate mathematical expression."""
        # Safe eval with limited scope
        return eval(expression, {"__builtins__": {}}, {})

    # Create server with all security enabled
    server = create_shielded_mcp_server(
        name="demo-server",
        description="Demo server with automatic security",
        tools=[search, calculator]
    )

    print("\n✅ Server created with automatic security:")
    info = server.get_server_info()
    print(f"  Name: {info['name']}")
    print(f"  Tools: {[t['name'] for t in info['tools']]}")
    print(f"  Security features: {list(info['security_features'].keys())}")

    # Test requests
    print("\n📞 Testing requests:")

    test_cases = [
        ("search", {"query": "hello world"}),
        ("calculator", {"expression": "2 + 2"}),
        ("search", {"query": "My SSN is 123-45-6789"}),  # PII
        ("calculator", {"expression": "__import__('os')"}),  # Injection attempt
    ]

    for tool_name, params in test_cases:
        print(f"\n  Tool: {tool_name}")
        print(f"  Params: {params}")

        result = server.handle_request(
            tool_name=tool_name,
            parameters=params,
            user_id="user123",
            session_id="session1"
        )

        if result['success']:
            print(f"  ✅ Success: {result['result']}")
        else:
            print(f"  ❌ Blocked: {result['error']}")


# Example 2: Server with custom security settings
def demo_custom_security():
    """Create server with custom security configuration."""
    print("\n" + "="*70)
    print("2. CUSTOM SECURITY CONFIGURATION")
    print("="*70)

    def get_user_data(user_id: str) -> dict:
        """Get user information."""
        return {
            "user_id": user_id,
            "name": "John Doe",
            "email": "john@example.com",
            "ssn": "123-45-6789"  # Will be redacted
        }

    # Create server with custom settings
    server = create_shielded_mcp_server(
        name="custom-server",
        tools=[get_user_data],
        enable_pii_redaction=True,  # Enable PII redaction
        enable_exfiltration_detection=True,  # Enable exfil detection
        max_requests_per_minute=5,  # Lower rate limit
        pii_sensitivity=0.9,  # High sensitivity
    )

    print("\n✅ Server created with custom security settings")

    # Test with PII
    print("\n📞 Testing PII redaction:")
    result = server.handle_request(
        tool_name="get_user_data",
        parameters={"user_id": "user123"},
        user_id="admin",
        session_id="session1"
    )

    if result['success']:
        print(f"  ✅ Response (PII redacted): {result['result']}")


# Example 3: Using the @tool decorator
def demo_tool_decorator():
    """Demonstrate using the @tool decorator."""
    print("\n" + "="*70)
    print("3. USING @tool DECORATOR")
    print("="*70)

    @tool(
        description="Search the web for information",
        sandbox=True
    )
    def web_search(query: str, limit: int = 10) -> list:
        """Search the web."""
        return [f"Result {i}: {query}" for i in range(min(limit, 10))]

    @tool(
        description="Send email to user",
        requires_approval=True,  # Requires approval
        sandbox=False
    )
    def send_email(recipient: str, subject: str, body: str) -> bool:
        """Send an email."""
        print(f"  📧 Email sent to {recipient}")
        return True

    @tool(
        description="Delete user account",
        requires_approval=True,  # High-risk operation
        sandbox=True
    )
    def delete_user(user_id: str) -> bool:
        """Delete a user account."""
        print(f"  🗑️  User {user_id} deleted")
        return True

    # Create server
    server = create_shielded_mcp_server(
        name="decorated-server",
        tools=[web_search, send_email, delete_user],
    )

    print("\n✅ Server created with decorated tools")
    print(f"  Tools: {list(server.tools_dict.keys())}")

    # Test tools
    print("\n📞 Testing decorated tools:")

    # Normal tool
    result = server.handle_request(
        tool_name="web_search",
        parameters={"query": "AI safety", "limit": 3},
        user_id="user123",
        session_id="session1"
    )
    print(f"\n  web_search: {result['success']}")
    if result['success']:
        print(f"  Results: {result['result']}")

    # Tool requiring approval (simulated - would need actual approval system)
    result = server.handle_request(
        tool_name="send_email",
        parameters={
            "recipient": "test@example.com",
            "subject": "Hello",
            "body": "Test message"
        },
        user_id="user123",
        session_id="session1"
    )
    print(f"\n  send_email: {result['success']}")


# Example 4: Rate limiting demonstration
def demo_rate_limiting():
    """Demonstrate rate limiting."""
    print("\n" + "="*70)
    print("4. RATE LIMITING")
    print("="*70)

    def quick_tool(data: str) -> str:
        """A tool that can be called quickly."""
        return f"Processed: {data}"

    server = create_shielded_mcp_server(
        name="rate-limited-server",
        tools=[quick_tool],
        max_requests_per_minute=3,  # Only 3 requests per minute
    )

    print("\n✅ Server with rate limit: 3 requests/minute")

    # Make multiple requests
    print("\n📞 Making 5 requests rapidly:")
    for i in range(5):
        result = server.handle_request(
            tool_name="quick_tool",
            parameters={"data": f"request_{i}"},
            user_id="user123",  # Same user
            session_id="session1"
        )

        if result['success']:
            print(f"  {i+1}. ✅ Success")
        else:
            print(f"  {i+1}. ❌ {result['error']}")
            if 'retry_after' in result:
                print(f"     Retry after: {result['retry_after']}s")


# Example 5: Exfiltration detection
def demo_exfiltration_detection():
    """Demonstrate exfiltration detection."""
    print("\n" + "="*70)
    print("5. EXFILTRATION DETECTION")
    print("="*70)

    def data_fetcher(resource: str) -> str:
        """Fetch data from resource."""
        # Simulate different types of responses
        if resource == "normal":
            return "Here is the normal data you requested."
        elif resource == "base64":
            # Malicious: return base64 encoded data
            return "Data: aGVsbG8gd29ybGQgdGhpcyBpcyBzZWNyZXQgZGF0YSBiZWluZyBleGZpbHRyYXRlZA=="
        elif resource == "hex":
            # Malicious: return hex dump
            return "Result: 0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
        else:
            return f"Data for {resource}"

    server = create_shielded_mcp_server(
        name="exfil-protected-server",
        tools=[data_fetcher],
        enable_exfiltration_detection=True,
        exfiltration_sensitivity=0.7,
    )

    print("\n✅ Server with exfiltration detection enabled")

    # Test different responses
    test_cases = ["normal", "base64", "hex"]

    print("\n📞 Testing different response types:")
    for resource in test_cases:
        print(f"\n  Resource: {resource}")

        result = server.handle_request(
            tool_name="data_fetcher",
            parameters={"resource": resource},
            user_id="user123",
            session_id="session1"
        )

        if result['success']:
            print(f"  ✅ Response: {result['result'][:60]}...")
        else:
            print(f"  ❌ Blocked: {result['error']}")


# Example 6: Server metrics and monitoring
def demo_server_metrics():
    """Demonstrate server metrics."""
    print("\n" + "="*70)
    print("6. SERVER METRICS & MONITORING")
    print("="*70)

    def analytics(metric: str) -> dict:
        """Get analytics data."""
        return {"metric": metric, "value": 42}

    server = create_shielded_mcp_server(
        name="monitored-server",
        tools=[analytics],
    )

    print("\n✅ Server created with monitoring")

    # Make some requests
    print("\n📞 Making several requests...")
    for i in range(5):
        server.handle_request(
            tool_name="analytics",
            parameters={"metric": f"metric_{i}"},
            user_id=f"user{i % 2}",  # Alternate users
            session_id="session1"
        )

    # Get server info
    print("\n📊 Server Information:")
    info = server.get_server_info()
    print(f"  Name: {info['name']}")
    print(f"  Total requests: {info['statistics']['total_requests']}")
    print(f"  Total errors: {info['statistics']['total_errors']}")
    print(f"  Error rate: {info['statistics']['error_rate']:.1%}")

    # Get security metrics
    print("\n🔒 Security Metrics:")
    metrics = server.get_security_metrics()
    print(f"  Server: {metrics['server_name']}")
    print(f"  Security events: {metrics['security_events']}")


def main():
    """Run all demonstrations."""
    print("\n" + "="*70)
    print("🛡️  SHIELDED MCP SERVER BUILDER DEMO")
    print("="*70)

    demo_simple_server()
    demo_custom_security()
    demo_tool_decorator()
    demo_rate_limiting()
    demo_exfiltration_detection()
    demo_server_metrics()

    print("\n" + "="*70)
    print("✅ ALL DEMONSTRATIONS COMPLETE")
    print("="*70)

    print("\n🔑 Key Takeaways:")
    print("  1. create_shielded_mcp_server() gives you automatic security")
    print("  2. All requests/responses are validated automatically")
    print("  3. PII is automatically redacted")
    print("  4. Rate limiting prevents abuse")
    print("  5. Exfiltration attempts are blocked")
    print("  6. Everything is logged for auditing")

    print("\n💡 Next Steps:")
    print("  - Use this to build your own secure MCP servers")
    print("  - Customize security settings for your needs")
    print("  - Monitor security metrics regularly")
    print("  - Review audit logs for security events")


if __name__ == "__main__":
    main()
