import argparse
import time
import logging
import sys
import os
from communication.logger_utils import setup_custom_logger
from communication.mqtt_client_handler import MQTTClientHandler
from secure_aggregation.sa_client_orchestrator import SecureAggregationClient
from fl_baseline.vanillaFL_client import VanillaFLClient
from fl_core.model import MockSecAggModel
from metrics.metrics_collector import MetricsCollector

from crypto.stacks.stack_a import Stack1Crypto
from crypto.stacks.stack_b import Stack2Crypto
from crypto.stacks.stack_c import Stack3Crypto


def main():
    parser = argparse.ArgumentParser(description="FL Client Entry Point")
    parser.add_argument("--id",    type=str, required=True, help="Client ID")
    parser.add_argument("--ip",    type=str, required=True, help="MQTT Broker IP")
    parser.add_argument("--stack", type=str, required=True, choices=["A", "B", "C"])
    parser.add_argument("--ca",    type=str, default="/app/certs/ca.crt")
    parser.add_argument("--cert",  type=str, default="/app/certs/client.crt")
    parser.add_argument("--key",   type=str, default="/app/certs/client.key")
    parser.add_argument("--results-dir", type=str, default="metrics/results",
                        help="Directory to write metrics CSV files (default: metrics/results/)")
    args = parser.parse_args()

    logger = setup_custom_logger(args.id)
    mode   = os.getenv("PROTOCOL_MODE", "secagg").lower()

    # ── Determine metric label ──────────────────────────────────────────────
    if mode == "baseline":
        metric_mode = f"baseline_{args.id}"
    else:
        metric_mode = f"stack_{args.stack.lower()}_{args.id}"

    collector = MetricsCollector(mode=metric_mode, output_dir=args.results_dir)

    try:
        mqtt_handler = MQTTClientHandler(
            client_id=args.id,
            broker_ip=args.ip,
            ca_path=args.ca,
            cert_path=args.cert,
            key_path=args.key,
        )

        ml_model = MockSecAggModel(client_id=args.id, num_features=10)

        if mode == "baseline":
            logger.info(f"--- [{args.id}] BOOTING IN VANILLA FL MODE ---")
            orchestrator = VanillaFLClient(
                client_id=args.id,
                mqtt_handler=mqtt_handler,
                local_model=ml_model,
            )
        else:
            logger.info(f"--- [{args.id}] BOOTING IN SECURE AGGREGATION MODE (STACK {args.stack}) ---")

            if args.stack == "A":
                crypto_stack = Stack1Crypto(args.id)
            elif args.stack == "B":
                crypto_stack = Stack2Crypto(args.id)
            else:
                crypto_stack = Stack3Crypto(args.id)

            orchestrator = SecureAggregationClient(
                client_id=args.id,
                mqtt_handler=mqtt_handler,
                crypto_stack=crypto_stack,
                ml_model=ml_model,
                metrics=collector,
            )

        mqtt_handler.set_orchestrator(orchestrator)
        mqtt_handler.start()  # Connect to broker FIRST

        if mode == "baseline":
            logger.info(f"[{args.id}] Baseline standby. Waiting for server ignition...")
        else:
            # Trigger Round 0 AFTER the broker connection is established.
            # Only the command key matters — _execute_round_0 ignores everything else.
            logger.info(f"[{args.id}] SecAgg Round 0 triggered.")
            orchestrator._execute_round_0(data={"command": "ignite_fl"})

        while True:
            time.sleep(1)

    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        collector.print_summary()
        mqtt_handler.stop()


if __name__ == "__main__":
    main()