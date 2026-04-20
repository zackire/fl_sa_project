import argparse
import time
from communication.logger_utils import setup_custom_logger
from communication.mqtt_server_handler import MQTTServerHandler
from secure_aggregation.sa_server_orchestrator import SecureAggregationServer
from crypto.stacks.stack_a import Stack1Crypto 
from crypto.stacks.stack_b import Stack2Crypto
from crypto.stacks.stack_c import Stack3Crypto

def main():
    parser = argparse.ArgumentParser(description="FL Secure Aggregation Server")
    parser.add_argument("--ip", type=str, required=True, help="MQTT Broker IP")
    parser.add_argument("--k", type=int, required=True, help="Expected number of clients (K)")
    parser.add_argument("--t", type=int, required=True, help="Threshold of surviving clients (T)")
    parser.add_argument("--stack", type=str, required=True, choices=["A", "B", "C"], help="Crypto Stack")
    parser.add_argument("--ca", type=str, required=False, help="Path to CA certificate for mTLS")
    parser.add_argument("--cert", type=str, required=False, help="Path to Client certificate for mTLS")
    parser.add_argument("--key", type=str, required=False, help="Path to Client key for mTLS")
    args = parser.parse_args()
    logger = setup_custom_logger("server")

    if args.stack == "A":
        crypto_stack = Stack1Crypto("server")
    elif args.stack == "B":
        crypto_stack = Stack2Crypto("server")
    else:
        crypto_stack = Stack3Crypto("server")

    mqtt_handler = MQTTServerHandler(
        broker_ip=args.ip,
        ca_path=args.ca,
        cert_path=args.cert,
        key_path=args.key
    )
    
    orchestrator = SecureAggregationServer(
        mqtt_handler=mqtt_handler, 
        t_threshold=args.t, 
        expected_k=args.k, 
        crypto_stack=crypto_stack
    )
    
    mqtt_handler.set_orchestrator(orchestrator)
    mqtt_handler.start()
    
    logger.info(f"Server started. Expecting {args.k} clients with threshold {args.t}. Press Ctrl+C to exit.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
        mqtt_handler.stop()

if __name__ == "__main__":
    main()