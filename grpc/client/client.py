import grpc
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

sys.path.append("..")
from libs import verification_pb2_grpc, verification_pb2

BASE_DIR = Path(__file__).resolve().parent.parent.parent

load_dotenv(dotenv_path=os.path.join(BASE_DIR, '.env'))

server_path = os.environ.get("GRPC_SERVER_PATH", "localhost:50051")

channel = grpc.insecure_channel(server_path)
stub = verification_pb2_grpc.AuthStub(channel)

response = stub.ValidateToken(verification_pb2.TokenValidatorRequest(bearer="TtncWvHvFoquEQthnxXUv5tpeSUbc3"))
print("Response message: ", response.msg)
print("Response success: ", response.success)
