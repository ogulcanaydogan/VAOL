"""Example: VAOL Python SDK with OpenAI auto-instrumentation.

Demonstrates two patterns:
1. Auto-instrumented OpenAI client (zero-code-change integration)
2. Manual DecisionRecord construction and submission

Usage:
    pip install vaol httpx
    python main.py

Requires:
- VAOL server at http://localhost:8080 (--auth-mode disabled --policy-mode allow-all)
- For Pattern 1: OPENAI_API_KEY environment variable (or mock)
"""

import vaol


def manual_record_example():
    """Pattern 2: Build and submit a record manually."""
    print("=== VAOL Python Example (Manual Record) ===\n")

    client = vaol.VAOLClient("http://localhost:8080")

    # Check server health
    health = client.health()
    print(f"1. Server health: {health['status']}")
    print(f"   Records: {health.get('record_count', 0)}\n")

    # Build a DecisionRecord
    record = vaol.DecisionRecord(
        identity=vaol.Identity(
            tenant_id="example-org",
            subject="demo-user",
            subject_type="user",
        ),
        model=vaol.ModelInfo(
            provider="openai",
            name="gpt-4o",
            version="2025-01-01",
        ),
        parameters=vaol.Parameters(
            temperature=0.7,
            max_tokens=1024,
        ),
        prompt_context=vaol.PromptContext(
            user_prompt_hash=vaol.sha256_hash("What is the capital of France?"),
            system_prompt_hash=vaol.sha256_hash("You are a helpful assistant."),
            message_count=2,
        ),
        policy_context=vaol.PolicyContext(
            policy_decision=vaol.PolicyDecision.ALLOW,
        ),
        output=vaol.Output(
            output_hash=vaol.sha256_hash("The capital of France is Paris."),
            mode=vaol.OutputMode.HASH_ONLY,
            output_tokens=8,
            finish_reason="stop",
            latency_ms=245.3,
        ),
    )

    # Append to ledger
    print("2. Appending DecisionRecord...")
    receipt = client.append(record)
    print(f"   request_id: {record.request_id}")
    print(f"   sequence:   {receipt.get('sequence_number')}\n")

    # Retrieve
    print("3. Retrieving record...")
    stored = client.get(record.request_id)
    print(f"   tenant: {stored.get('record', {}).get('identity', {}).get('tenant_id')}")
    print(f"   model:  {stored.get('record', {}).get('model', {}).get('name')}\n")

    # Verify
    print("4. Verifying DSSE envelope...")
    envelope = stored.get("envelope", {})
    result = client.verify(envelope)
    print(f"   Valid: {result.get('valid')}")
    for check in result.get("checks", []):
        status = "PASS" if check.get("passed") else "FAIL"
        print(f"   - {check.get('name')}: {status}")
    print()

    # Checkpoint
    print("5. Fetching checkpoint...")
    cp = client.checkpoint()
    print(f"   Root: {cp.get('root_hash', 'N/A')}")
    print(f"   Tree size: {cp.get('tree_size', 'N/A')}\n")

    # Export
    print("6. Exporting audit bundle...")
    bundle = client.export(tenant_id="example-org")
    records = bundle.get("records", [])
    print(f"   Bundle contains {len(records)} record(s)")

    print("\nDone.")


def instrumented_example():
    """Pattern 1: Auto-instrumented OpenAI client.

    Uncomment and set OPENAI_API_KEY to run against a real LLM.
    """
    # from openai import OpenAI
    #
    # openai_client = OpenAI()
    # vaol_client = vaol.VAOLClient("http://localhost:8080")
    #
    # # Wrap the client — every call now emits a DecisionRecord
    # wrapped = vaol.instrument_openai(
    #     openai_client,
    #     vaol_client,
    #     tenant_id="example-org",
    #     subject="demo-user",
    # )
    #
    # response = wrapped.chat.completions.create(
    #     model="gpt-4o",
    #     messages=[
    #         {"role": "system", "content": "You are a helpful assistant."},
    #         {"role": "user", "content": "What is the capital of France?"},
    #     ],
    #     temperature=0.7,
    # )
    # print(f"LLM response: {response.choices[0].message.content}")
    # print("DecisionRecord was automatically emitted to VAOL.")
    pass


if __name__ == "__main__":
    manual_record_example()
