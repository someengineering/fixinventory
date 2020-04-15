import logging
import threading
from datetime import datetime, timezone
from cloudkeeper.graph import Graph
from cloudkeeper.baseplugin import BasePlugin
from cloudkeeper.baseresources import BaseCloud, BaseAccount, BaseRegion
from cloudkeeper_plugin_aws.resources import AWSALBTargetGroup
from cloudkeeper.args import ArgumentParser
from cloudkeeper.event import Event, EventType, add_event_listener, remove_event_listener

log = logging.getLogger('cloudkeeper.' + __name__)


class TagAWSAlbTargetGroupsPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = 'tag_aws_alb_target_groups'
        self.exit = threading.Event()
        self.run_lock = threading.Lock()
        if ArgumentParser.args.tag_aws_alb_target_groups:
            log.debug(f'AWS ALB Target Group ctime Tagger plugin initializing')
            add_event_listener(EventType.SHUTDOWN, self.shutdown)
            add_event_listener(EventType.COLLECT_FINISH, self.aws_alb_target_group_tagger, blocking=False, timeout=30)
        else:
            self.exit.set()

    def __del__(self):
        remove_event_listener(EventType.COLLECT_FINISH, self.aws_alb_target_group_tagger)
        remove_event_listener(EventType.SHUTDOWN, self.shutdown)

    def go(self):
        self.exit.wait()

    def aws_alb_target_group_tagger(self, event: Event):
        if not self.run_lock.acquire(blocking=False):
            log.error(f'AWS ALB Target Group ctime Tagger is already running')
            return

        graph = event.data
        log.info(f'AWS ALB Target Group ctime Tagger called')
        try:
            self.tag_target_groups(graph)
        except Exception:
            raise
        finally:
            self.run_lock.release()

    def tag_target_groups(self, graph: Graph):
        now = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
        with graph.lock.read_access:
            for node in graph.nodes:
                if not isinstance(node, AWSALBTargetGroup):
                    continue

                if 'cloudkeeper:ctime' not in node.tags:
                    cloud = node.cloud(graph)
                    account = node.account(graph)
                    region = node.region(graph)
                    if isinstance(cloud, BaseCloud) and isinstance(account, BaseAccount) and isinstance(region, BaseRegion):
                        log.debug((f'AWS ALB Target Group {node.id} in cloud {cloud.name} account {account.name} region {region.name}'
                                   f' has no cloudkeeper:ctime tag - setting it because ctime is not available via the AWS API'))
                        node.tags['cloudkeeper:ctime'] = now
                    else:
                        log.error(f'AWS ALB Target Group {node.id} has no valid cloud, account or region associated with it')

    @staticmethod
    def add_args(arg_parser: ArgumentParser) -> None:
        arg_parser.add_argument('--tag-aws-alb-target-groups', help='Tag AWS ALB Target Groups with ctime (default: False)', dest='tag_aws_alb_target_groups', action='store_true', default=False)

    def shutdown(self, event: Event):
        log.debug(f'Received event {event.event_type} - shutting down AWS ALB Target Group tagging plugin')
        self.exit.set()
