import service.certificateDriver as batchstart
import sys


if __name__ == '__main__':
    try:
        batchstart.certificatedriver()
    except Exception as e:
        print(e)
        sys.exit(1)