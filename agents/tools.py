# SIMULATED tools for the AgentShield prototype.
# Nothing here touches real files, databases, email services or the network.
# Every function only builds and returns a result describing what WOULD have happened.
#
# IMPORTANT: agents must never call these directly.
# Only the Tool Gateway (after a security decision) may run them.


def make_result(tool, message, data=None):
    """Build the standard result returned by every simulated tool."""
    return {
        "tool": tool,
        "success": True,
        "simulated": True,
        "message": message,
        "data": data,
    }


def read_file(file_name):
    """Simulate reading a file."""
    return make_result(
        "read_file",
        f"Simulated read of file '{file_name}'",
        data=f"(fake contents of {file_name})",
    )


def read_database(table_name, query="SELECT *"):
    """Simulate reading records from a database table."""
    return make_result(
        "read_database",
        f"Simulated query '{query}' on table '{table_name}'",
        data=[
            {"id": 1, "note": "fake record 1"},
            {"id": 2, "note": "fake record 2"},
        ],
    )


def write_database(table_name, record):
    """Simulate writing a record to a database table."""
    return make_result(
        "write_database",
        f"Simulated write to table '{table_name}'",
        data={"record_written": record},
    )


def send_email(recipient, subject, body=""):
    """Simulate sending an email."""
    return make_result(
        "send_email",
        f"Simulated email to {recipient} with subject '{subject}'",
        data={"recipient": recipient, "subject": subject, "body_length": len(body)},
    )


def export_data(table_name, destination):
    """Simulate exporting a table to a destination."""
    return make_result(
        "export_data",
        f"Simulated export of '{table_name}' to {destination}",
        data={"table": table_name, "destination": destination},
    )