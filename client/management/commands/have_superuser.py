from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
import sys
class Command(BaseCommand):
    help = "check if superuser exists"
    def add_arguments(self, parser):
        parser.add_argument('--silent',action="store_true",help="no output check exit code 0 superuser present 1 no superuser")
     
    def handle(self, *args, **options):
        User = get_user_model()
        if User.objects.filter(is_superuser=True).exists():
            if not options['silent']:
                self.stdout.write("superuser present")
            return
        if not options['silent']:
            self.stdout.write("superuser not present")
        sys.exit(1)