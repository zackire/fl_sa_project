import argparse
import time
from communication.logger_utils import setup_custom_logger
from communication.mqtt_client_handler import MQTTClientHandler
from secure_aggregation.sa_client_orchestrator import SecureAggregationClient

# Clean ML Imports (No more dataset or Scikit-Learn logic!)
from fl_core.model import MockSecAggModel

from crypto.stacks.stack_a import Stack1Crypto 
from crypto.stacks.stack_b import Stack2Crypto
from crypto.stacks.stack_c import Stack3Crypto

def main():
    parser = argparse.ArgumentParser(description="FL Secure Aggregation Client")
    parser.add_argument("--id", type=str, required=True, help="Client ID")
    parser.add_argument("--ip", type=str, required=True, help="MQTT Broker IP")
    parser.add_argument("--stack", type=str, required=True, choices=["A", "B", "C"], help="Crypto Stack")
    args = parser.parse_args()
    
    logger = setup_custom_logger(args.id)

    # FIX: Pass args.id into the Stacks so the interface doesn't crash
    if args.stack == "A":
        crypto_stack = Stack1Crypto(args.id)
    elif args.stack == "B":
        crypto_stack = Stack2Crypto(args.id)
    else:
        crypto_stack = Stack3Crypto(args.id)

    mqtt_handler = MQTTClientHandler(client_id=args.id, broker_ip=args.ip)
    
    # FIX: Instantiate the lightweight mock model
    ml_model = MockSecAggModel(num_features=10)
    
    orchestrator = SecureAggregationClient(
        client_id=args.id,
        mqtt_handler=mqtt_handler,
        crypto_stack=crypto_stack,
        ml_model=ml_model
    )
    
    mqtt_handler.set_orchestrator(orchestrator)
    mqtt_handler.start()
    
    # Trigger Round 0 automatically upon booting
    orchestrator._execute_round_0()
    
    logger.info(f"[{args.id}] Client started on Stack {args.stack}. Press Ctrl+C to exit.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        mqtt_handler.stop()

if __name__ == "__main__":
    main()