test:
		nosetests -s

release:
		python setup.py sdist register upload
