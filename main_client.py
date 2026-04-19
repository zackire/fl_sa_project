import argparse
import time
from communication.logger_utils import setup_custom_logger
from communication.mqtt_client_handler import MQTTClientHandler
from secure_aggregation.sa_client_orchestrator import SecureAggregationClient

from crypto.stacks.stack_a import Stack1Crypto
from crypto.stacks.stack_b import Stack2Crypto
from crypto.stacks.stack_c import Stack3Crypto

# Updated to match the actual model name identified in the audit
from fl_core.model import AnomalyDetectionLR
from fl_core.dataset import load_local_data

def main():
    parser = argparse.ArgumentParser(description="FL Secure Aggregation Client")
    parser.add_argument("--id", type=str, required=True, help="Unique Client ID (e.g., client_1)")
    parser.add_argument("--ip", type=str, required=True, help="MQTT Broker IP")
    parser.add_argument("--stack", type=str, required=True, choices=["A", "B", "C"], help="Crypto Stack")
    parser.add_argument("--ca", type=str, required=False, help="Path to CA certificate for mTLS")
    parser.add_argument("--cert", type=str, required=False, help="Path to Client certificate for mTLS")
    parser.add_argument("--key", type=str, required=False, help="Path to Client key for mTLS")
    args = parser.parse_args()
    logger = setup_custom_logger(args.id)

    if args.stack == "A":
        crypto_stack = Stack1Crypto()
    elif args.stack == "B":
        crypto_stack = Stack2Crypto()
    else:
        crypto_stack = Stack3Crypto()

    ml_model = AnomalyDetectionLR()
    X_train, y_train = load_local_data(client_id=args.id)

    mqtt_handler = MQTTClientHandler(
        client_id=args.id, 
        broker_ip=args.ip,
        ca_path=args.ca,
        cert_path=args.cert,
        key_path=args.key
    )
    
    orchestrator = SecureAggregationClient(
        client_id=args.id, 
        crypto_stack=crypto_stack, 
        mqtt_handler=mqtt_handler, 
        ml_model=ml_model
    )
    
    mqtt_handler.set_orchestrator(orchestrator)
    mqtt_handler.start()
    
    logger.info(f"Client {args.id} started using Stack {args.stack}. Awaiting Round 0 trigger.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down client...")
        mqtt_handler.stop()

if __name__ == "__main__":
    main()