# global Celery options that apply to all configurations

# enable the pickle serializer
task_serializer = 'pickle'
result_serializer = 'pickle'
accept_content = ['pickle']
CELERY_ACCEPT_CONTENT = ['pickle', 'json', 'msgpack', 'yaml']  #pickle is a security threat so this is required
