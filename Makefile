localtest:
	nosetests tests/*.py -sx;
gitlabtest:
	nosetests tests/*.py -sx;
coverage:
	rm -rf coverage .coverage; mkdir coverage; nosetests -qsx --with-coverage --cover-tests --cover-html-dir=coverage --cover-html tests/*.py; coverage report -m;
uninstall:
	cat files.txt | xargs sudo rm -rf;
	rm -rf files.txt;
install:
	sudo python3 setup.py install --record files.txt;
clean:
	sudo rm -rf coverage docs build ansible_multivault.egg-info .coverage dist;

