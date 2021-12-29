import grpc
import sys
sys.path.append("..")
from libs import verification_pb2_grpc, verification_pb2



channel = grpc.insecure_channel("localhost:50051")
stub = verification_pb2_grpc.AuthStub(channel)

response = stub.ValidateToken(verification_pb2.TokenValidatorRequest(bearer="TtncWvHvFoquEQthnxXUv5tpeSUbc3"))
print("Response message: ", response.msg)
print("Response success: ", response.success)