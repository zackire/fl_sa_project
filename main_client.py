import argparse
import time
import logging
import sys
import os
from communication.logger_utils import setup_custom_logger
from communication.mqtt_client_handler import MQTTClientHandler
from secure_aggregation.sa_client_orchestrator import SecureAggregationClient
from fl_baseline.vanillaFL_client import VanillaFLClient
from fl_core.model import LocalLogisticRegressionModel  # real model
from metrics.metrics_collector import MetricsCollector

from crypto.stacks.stack_a import Stack1Crypto
from crypto.stacks.stack_b import Stack2Crypto
from crypto.stacks.stack_c import Stack3Crypto

# ─── Default dataset path ─────────────────────────────────────────────────────
# Override via --data-path CLI flag or DATA_PATH environment variable.
DEFAULT_DATA_PATH = os.getenv("DATA_PATH", "/data/Train_Test_Network.csv")


def main():
    parser = argparse.ArgumentParser(description="FL Client Entry Point")
    parser.add_argument("--id",        type=str,   required=True,  help="Client ID (client1 / client2 / client3)")
    parser.add_argument("--ip",        type=str,   required=True,  help="MQTT Broker IP")
    parser.add_argument("--stack",     type=str,   required=True,  choices=["A", "B", "C"])
    parser.add_argument("--ca",        type=str,   default="/app/certs/ca.crt")
    parser.add_argument("--cert",      type=str,   default="/app/certs/client.crt")
    parser.add_argument("--key",       type=str,   default="/app/certs/client.key")
    parser.add_argument("--data-path", type=str,   default=DEFAULT_DATA_PATH,
                        help="Path to Train_Test_Network.csv (default: /data/Train_Test_Network.csv)")
    parser.add_argument("--epochs",    type=int,   default=int(os.getenv("LOCAL_EPOCHS", 3)),
                        help="Local training epochs per FL round (default: 3)")
    parser.add_argument("--lr",        type=float, default=float(os.getenv("LEARNING_RATE", 0.01)),
                        help="SGD learning rate (default: 0.01)")
    parser.add_argument("--results-dir", type=str, default="metrics/results/utilities",
                        help="Directory to write metrics CSV files (default: metrics/results/utilities)")
    args = parser.parse_args()

    logger = setup_custom_logger(args.id)
    mode   = os.getenv("PROTOCOL_MODE", "secagg").lower()

    # ── Metrics collector ────────────────────────────────────────────────────
    if mode == "baseline":
        collector = MetricsCollector(
            protocol="baseline",
            stack="",
            role="client",
            node_id=args.id,
            output_dir=args.results_dir,
        )
    else:
        collector = MetricsCollector(
            protocol="secagg",
            stack=f"stack{args.stack.upper()}",
            role="client",
            node_id=args.id,
            output_dir=args.results_dir,
        )

    try:
        mqtt_handler = MQTTClientHandler(
            client_id=args.id,
            broker_ip=args.ip,
            ca_path=args.ca,
            cert_path=args.cert,
            key_path=args.key,
        )

        # ── Real model: loads and preprocesses its 1/3 partition on construction ──
        ml_model = LocalLogisticRegressionModel(
            client_id=args.id,
            data_path=args.data_path,
            local_epochs=args.epochs,
            learning_rate=args.lr,
        )

        # Run an initial fit() so the client always has real trained weights
        # before the first FL round begins.  The server's first broadcast will
        # warm-start from these via set_weights() + fit().
        logger.info(f"[{args.id}] Running initial local fit before connecting …")
        ml_model.fit()

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
            logger.info(f"[{args.id}] SecAgg Round 0 triggered.")
            orchestrator._execute_round_0(data={"command": "ignite_fl"})

        while True:
            time.sleep(1)

    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        sys.exit(1)
    except KeyboardInterrupt:
        collector.print_summary()
        mqtt_handler.stop()


if __name__ == "__main__":
    main()