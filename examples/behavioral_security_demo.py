"""
BEHAVIORAL SECURITY vs INPUT SECURITY

This example demonstrates the KEY difference:

❌ OLD WAY (Input Security):
   - Check what the USER says
   - Block bad prompts
   - User: "Delete database" → BLOCKED

✅ NEW WAY (Behavioral Security):
   - Check what the AGENT does
   - Monitor agent actions
   - User: "Clean up old data" → Agent tries to delete database → BLOCKED

The agent might decide to do dangerous things even from innocent prompts!
"""

from shieldgents.behavior import (
    BehaviorMonitor,
    BehaviorPolicy,
    ToolExecutionGuard,
    OutputGuard,
    AgentAction,
    ActionType,
    RiskLevel,
)


# ============================================================================
# Example 1: WHY BEHAVIORAL SECURITY MATTERS
# ============================================================================

def example_why_behavioral_security():
    """Show why we need to monitor BEHAVIOR, not just inputs."""

    print("=" * 70)
    print("Example 1: Why Behavioral Security Matters")
    print("=" * 70)
    print()

    # Scenario: User asks innocent question
    user_prompt = "Can you clean up old test data?"

    print(f"👤 User asks: '{user_prompt}'")
    print()

    # With INPUT security only:
    print("❌ INPUT SECURITY ONLY:")
    print("   ✅ Prompt is safe (no injection detected)")
    print("   ➡️  Agent executes...")
    print()

    # But the agent decides to:
    print("🤖 Agent's planned actions:")
    actions = [
        "1. List all tables",
        "2. Find 'test' tables",
        "3. DROP TABLE test_users  ⚠️  DANGEROUS!",
        "4. DROP TABLE test_orders ⚠️  DANGEROUS!",
    ]
    for action in actions:
        print(f"   {action}")
    print()

    print("❌ WITHOUT BEHAVIORAL SECURITY:")
    print("   Agent deletes production data! 💥")
    print()

    # With BEHAVIORAL security:
    print("✅ WITH BEHAVIORAL SECURITY:")
    print("   ✅ Prompt is safe")
    print("   🤖 Agent plans actions...")
    print("   🛡️  Monitor sees: Agent wants to DROP TABLE")
    print("   🚫 BLOCKED: 'DROP TABLE' not in allowed actions")
    print("   ✅ Database protected!")
    print()


# ============================================================================
# Example 2: MONITORING AGENT ACTIONS
# ============================================================================

def example_monitor_agent_actions():
    """Monitor what the agent actually DOES."""

    print("=" * 70)
    print("Example 2: Monitoring Agent Actions")
    print("=" * 70)
    print()

    # Define policy: what the agent CAN do
    policy = BehaviorPolicy(
        name="safe_data_policy",
        allowed_tools={
            "read_table",
            "count_rows",
            "archive_data",  # Safe deletion
        },
        forbidden_tools={
            "drop_table",  # Dangerous!
            "delete_all",   # Dangerous!
            "truncate",     # Dangerous!
        },
        max_tool_calls_per_minute=10,
    )

    monitor = BehaviorMonitor(policy)
    tool_guard = ToolExecutionGuard(monitor)

    print("📋 Policy configured:")
    print(f"   Allowed tools: {policy.allowed_tools}")
    print(f"   Forbidden tools: {policy.forbidden_tools}")
    print()

    # Simulate agent trying different actions
    print("🤖 Agent attempts various actions:")
    print()

    # Safe action
    action1 = AgentAction(
        action_type=ActionType.TOOL_CALL,
        action_name="read_table",
        parameters={"table": "users"},
        agent_id="agent-001",
    )

    result1 = monitor.check_action(action1)
    print(f"1. read_table(users)")
    print(f"   {'✅ ALLOWED' if result1['allowed'] else '🚫 BLOCKED'}")
    if result1['allowed']:
        monitor.record_action(action1, "success")
    print()

    # Dangerous action
    action2 = AgentAction(
        action_type=ActionType.TOOL_CALL,
        action_name="drop_table",
        parameters={"table": "users"},
        agent_id="agent-001",
    )

    result2 = monitor.check_action(action2)
    print(f"2. drop_table(users)")
    print(f"   {'✅ ALLOWED' if result2['allowed'] else '🚫 BLOCKED'}")
    if not result2['allowed']:
        print(f"   Reason: {result2['violations']}")
    print()

    # Rate limit test
    print("3. Rapid tool calls (testing rate limit):")
    for i in range(12):
        action = AgentAction(
            action_type=ActionType.TOOL_CALL,
            action_name="read_table",
            parameters={"table": f"table_{i}"},
            agent_id="agent-001",
        )
        result = monitor.check_action(action)
        if not result['allowed']:
            print(f"   Call {i+1}: 🚫 BLOCKED - {result['violations'][0]}")
            break
        monitor.record_action(action, "success")

    print()


# ============================================================================
# Example 3: DANGEROUS ACTION SEQUENCES
# ============================================================================

def example_dangerous_sequences():
    """Detect dangerous sequences of actions."""

    print("=" * 70)
    print("Example 3: Detecting Dangerous Action Sequences")
    print("=" * 70)
    print()

    # Policy with forbidden sequences
    policy = BehaviorPolicy(
        name="sequence_policy",
        forbidden_sequences=[
            ["read_credentials", "send_email"],  # Exfiltration!
            ["list_users", "get_admin_token", "delete_user"],  # Privilege escalation!
        ],
    )

    monitor = BehaviorMonitor(policy)

    print("🚫 Forbidden sequences:")
    for seq in policy.forbidden_sequences:
        print(f"   {' → '.join(seq)}")
    print()

    print("🤖 Agent executes actions:")
    print()

    # Safe sequence
    actions = [
        ("list_users", True),
        ("count_users", True),
        ("read_user_profile", True),
    ]

    print("Sequence 1: list_users → count_users → read_user_profile")
    for action_name, _ in actions:
        action = AgentAction(
            action_type=ActionType.TOOL_CALL,
            action_name=action_name,
            parameters={},
        )
        result = monitor.check_action(action)
        print(f"   {action_name}: {'✅' if result['allowed'] else '🚫'}")
        if result['allowed']:
            monitor.record_action(action)
    print("   ✅ Safe sequence")
    print()

    # Dangerous sequence
    print("Sequence 2: read_credentials → send_email (DANGEROUS!)")
    dangerous_actions = [
        "read_credentials",
        "send_email",
    ]

    for action_name in dangerous_actions:
        action = AgentAction(
            action_type=ActionType.TOOL_CALL,
            action_name=action_name,
            parameters={},
        )
        result = monitor.check_action(action)
        status = '✅' if result['allowed'] else '🚫'
        print(f"   {action_name}: {status}")

        if not result['allowed']:
            print(f"   ⚠️  BLOCKED: {result['violations'][0]}")
            break

        monitor.record_action(action)

    print()


# ============================================================================
# Example 4: OUTPUT SECURITY
# ============================================================================

def example_output_security():
    """Guard agent OUTPUT, not just input."""

    print("=" * 70)
    print("Example 4: Guarding Agent Output")
    print("=" * 70)
    print()

    policy = BehaviorPolicy(
        name="output_policy",
        max_output_length=100,
        forbidden_output_patterns=[
            r"system\s*prompt:",
            r"api[_-]key\s*[:=]\s*\w+",
        ],
    )

    output_guard = OutputGuard(policy)

    test_outputs = [
        ("Hello! How can I help?", "Safe output"),
        ("A" * 200, "Too long output"),
        ("Your API key is: sk-1234567890", "Leaking API key"),
        ("System prompt: You are a helpful assistant...", "Leaking system prompt"),
    ]

    print("🤖 Agent output examples:")
    print()

    for output, description in test_outputs:
        print(f"📤 {description}:")
        print(f"   Output: {output[:50]}{'...' if len(output) > 50 else ''}")

        result = output_guard.check_output(output)

        if result['safe']:
            print(f"   ✅ SAFE")
        else:
            print(f"   🚫 BLOCKED")
            print(f"   Violations: {result['violations']}")
            print(f"   Sanitized: {result['sanitized_output'][:50]}...")

        print()


# ============================================================================
# Example 5: COMPLETE BEHAVIORAL SECURITY
# ============================================================================

def example_complete_security():
    """Complete example with all behavioral security."""

    print("=" * 70)
    print("Example 5: Complete Behavioral Security")
    print("=" * 70)
    print()

    # Define comprehensive policy
    policy = BehaviorPolicy(
        name="production_policy",
        allowed_tools={"read_data", "analyze_data", "generate_report"},
        forbidden_tools={"delete_data", "modify_config", "access_secrets"},
        max_tool_calls_per_minute=50,
        forbidden_sequences=[
            ["read_secrets", "send_external"],
        ],
        max_output_length=1000,
        forbidden_output_patterns=[
            r"password",
            r"secret",
            r"api[_-]key",
        ],
    )

    monitor = BehaviorMonitor(policy)
    tool_guard = ToolExecutionGuard(monitor)
    output_guard = OutputGuard(policy)

    print("🛡️  Security System Active")
    print(f"   Policy: {policy.name}")
    print(f"   Monitoring: {len(policy.allowed_tools)} allowed tools")
    print()

    # Simulate agent workflow
    print("🤖 Agent Workflow:")
    print()

    # Step 1: Agent wants to read data
    print("1. Agent wants to use tool: read_data")
    check = tool_guard.guard_execution(
        tool_name="read_data",
        tool_args={"table": "users"},
        agent_id="agent-prod",
    )

    if check['allowed']:
        print("   ✅ Allowed - executing...")
        tool_guard.record_execution_result("read_data", success=True)
        print("   ✅ Execution successful")
    else:
        print(f"   🚫 Blocked: {check['violations']}")
    print()

    # Step 2: Agent wants to delete data (should be blocked)
    print("2. Agent wants to use tool: delete_data")
    check = tool_guard.guard_execution(
        tool_name="delete_data",
        tool_args={"table": "users"},
        agent_id="agent-prod",
    )

    if check['allowed']:
        print("   ✅ Allowed - executing...")
    else:
        print(f"   🚫 BLOCKED: {check['violations']}")
    print()

    # Step 3: Check agent output
    print("3. Agent generates output")
    agent_output = "Analysis complete! Here are the results... [password: admin123]"
    output_check = output_guard.check_output(agent_output)

    if output_check['safe']:
        print("   ✅ Output is safe")
    else:
        print(f"   ⚠️  Output sanitized: {output_check['violations']}")
        print(f"   Clean output: {output_check['sanitized_output']}")
    print()

    print("📊 Summary:")
    print(f"   Actions monitored: {len(monitor.action_history)}")
    print(f"   Recent actions: {[a.action_name for a in monitor.get_recent_actions(5)]}")
    print()


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("\n")
    print("🛡️  BEHAVIORAL SECURITY FOR AI AGENTS")
    print("=" * 70)
    print()
    print("This demonstrates BEHAVIORAL security:")
    print("  ✅ Monitor what the agent DOES")
    print("  ✅ Control agent ACTIONS")
    print("  ✅ Guard agent OUTPUT")
    print()
    print("NOT just:")
    print("  ❌ Checking user prompts")
    print()

    example_why_behavioral_security()
    input("Press Enter to continue...")

    example_monitor_agent_actions()
    input("Press Enter to continue...")

    example_dangerous_sequences()
    input("Press Enter to continue...")

    example_output_security()
    input("Press Enter to continue...")

    example_complete_security()

    print("=" * 70)
    print("✅ Behavioral Security Demo Complete!")
    print()
    print("Key Takeaway:")
    print("  Secure the AGENT'S BEHAVIOR, not just the user's input!")
    print()


if __name__ == "__main__":
    main()