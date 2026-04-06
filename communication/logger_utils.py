import logging
import os

def setup_custom_logger(name):
    formatter = logging.Formatter(fmt='%(asctime)s - [%(name)s] - %(levelname)s - %(message)s')

    # Ensure logs directory exists
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # File Handler
    file_handler = logging.FileHandler(f'logs/{name}.log')
    file_handler.setFormatter(formatter)

    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # Bind to the ROOT logger so all modules inherit this configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Prevent duplicate handlers
    root_logger.handlers = []
    
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    return logging.getLogger(name)