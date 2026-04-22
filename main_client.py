import argparse
import time
import logging
import sys
from communication.logger_utils import setup_custom_logger
from communication.mqtt_client_handler import MQTTClientHandler
from secure_aggregation.sa_client_orchestrator import SecureAggregationClient

# Clean ML Imports
from fl_core.model import MockSecAggModel

from crypto.stacks.stack_a import Stack1Crypto 
from crypto.stacks.stack_b import Stack2Crypto
from crypto.stacks.stack_c import Stack3Crypto

def main():
    parser = argparse.ArgumentParser(description="FL Secure Aggregation Client")
    parser.add_argument("--id", type=str, required=True, help="Client ID")
    parser.add_argument("--ip", type=str, required=True, help="MQTT Broker IP")
    parser.add_argument("--stack", type=str, required=True, choices=["A", "B", "C"], help="Crypto Stack")
    
    parser.add_argument("--ca", type=str, default="/app/certs/ca.crt")
    parser.add_argument("--cert", type=str, default="/app/certs/client.crt")
    parser.add_argument("--key", type=str, default="/app/certs/client.key")
    
    args = parser.parse_args()
    logger = setup_custom_logger(args.id)

    try:
        if args.stack == "A":
            crypto_stack = Stack1Crypto(args.id)
        elif args.stack == "B":
            crypto_stack = Stack2Crypto(args.id)
        else:
            crypto_stack = Stack3Crypto(args.id)

        mqtt_handler = MQTTClientHandler(
            client_id=args.id, 
            broker_ip=args.ip,
            ca_path=args.ca,
            cert_path=args.cert,
            key_path=args.key
        )
        
        ml_model = MockSecAggModel(num_features=10)
        
        orchestrator = SecureAggregationClient(
            client_id=args.id,
            mqtt_handler=mqtt_handler,
            crypto_stack=crypto_stack,
            ml_model=ml_model
        )
        
        mqtt_handler.set_orchestrator(orchestrator)
        mqtt_handler.start()

        ml_model.fit()
        local_weights = ml_model.get_weights()

        ignition_packet = {
            "command": "ignite_fl",
            "weights": local_weights
        }
        
        orchestrator._execute_round_0(data=ignition_packet)
        logger.info(f"[{args.id}] Round 0 triggered. Waiting for server...")

        while True:
            time.sleep(1)

    except FileNotFoundError as e:
        logger.error(f"Certificate file not found! Check your volume mounts: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        mqtt_handler.stop()

if __name__ == "__main__":
    main()