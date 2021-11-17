class DBOperationError(Exception):
    def __init__(self, message, *args, **kwargs):
        self.message = message
        super(DBOperationError, self).__init__(*args, **kwargs)
