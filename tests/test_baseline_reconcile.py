# -*- coding: utf-8 -*-
import subprocess
import tempfile
import unittest
from pathlib import Path
from ops import baseline_reconcile, release_guard

class BaselineReconcileTests(unittest.TestCase):
    def make_repo(self, root):
        repo=root/'repo'; repo.mkdir(); subprocess.run(['git','init','-q','-b','main'],cwd=repo,check=True); subprocess.run(['git','config','user.name','T'],cwd=repo,check=True); subprocess.run(['git','config','user.email','t@example.invalid'],cwd=repo,check=True)
        (repo/'bridge').mkdir(); (repo/'bridge/app.py').write_text('x=1\n'); (repo/'passenger_wsgi.py').write_text('from bridge.app import application\n')
        subprocess.run(['git','add','bridge/app.py','passenger_wsgi.py'],cwd=repo,check=True); subprocess.run(['git','commit','-qm','baseline'],cwd=repo,check=True); return repo
    def test_hash_only_diff_and_startup_signal(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); repo=self.make_repo(root); recovered=root/'recovered'; (recovered/'bridge').mkdir(parents=True); (recovered/'bridge/app.py').write_text('x=1\n'); (recovered/'passenger_wsgi.py').write_text('# current host startup\nfrom bridge.app import application\n'); (recovered/'install_server.sh').write_text('')
            result=baseline_reconcile.reconcile(recovered,repo,'main'); self.assertEqual(['install_server.sh'],result['added_paths']); self.assertEqual(['passenger_wsgi.py'],result['changed_paths']); self.assertTrue(result['startup_file_changed']); self.assertFalse(result['raw_file_content_recorded'])
    def test_secret_like_recovered_tree_blocks_reconciliation(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); repo=self.make_repo(root); recovered=root/'recovered'; recovered.mkdir(); (recovered/'config.py').write_text('BRIDGE_TOKEN=synthetic-value-1234567890\n')
            with self.assertRaises(release_guard.SafetyError): baseline_reconcile.reconcile(recovered,repo,'main')

if __name__=='__main__': unittest.main()
