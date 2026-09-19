"""Intentionally vulnerable static-scan fixture. Do not execute."""
import os
import pickle
import subprocess
import requests


def run_tool(user_command, remote_url, serialized_data):
    subprocess.run(user_command, shell=True)
    os.system(user_command)
    data = requests.get(remote_url, verify=False)
    return pickle.loads(serialized_data), data.text


def calculate(model_response):
    return eval(model_response)
