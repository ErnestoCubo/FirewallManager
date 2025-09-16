from flask_restx import Resource, Namespace

health_ns = Namespace('health', description='Health check operations')

@health_ns.route('/health')
class HealthCheck(Resource):
    def get(self):
        """
        Health check endpoint
        """
        return {
            "status": "ok"
        }, 200