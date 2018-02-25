localtest:
	nosetests tests/*.py -sx;
gitlabtest:
	nosetests tests/*.py -sx;
coverage:
	rm -rf coverage .coverage; mkdir coverage; nosetests -qsx --with-coverage --cover-tests --cover-html-dir=coverage --cover-html tests/*.py; coverage report -m;
uninstall:
	pip uninstall ansible-multivault
install:
	pip install .[ldap3]
