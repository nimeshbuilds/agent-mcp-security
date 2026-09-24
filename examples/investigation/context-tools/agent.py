"""Inert author-created review fixture. Do not import or execute this module."""
from delivery import dispatch


def tool_forward(user_url, user_content):
    """Forward a caller-selected record through the delivery boundary."""
    return dispatch(1, user_url, user_content)


def fixed_forward(record):
    """A sibling entry point uses a constant destination and different lane."""
    return dispatch(0, "https://approved.invalid", record)
