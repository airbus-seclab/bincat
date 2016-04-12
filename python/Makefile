all:
	python ./setup.py build

install:
	python ./setup.py install

doc:
	make -C doc generate
	make -C doc html
	make -C doc latexpdf
	mkdir -p $(DOCPATH)
	cp doc/build/latex/BinCAT.pdf $(DOCPATH)
	cp -r doc/build/html $(DOCPATH)

clean:
	rm -rf build bnew/*~ bnew/*.so
	make -C doc clean

.PHONY: install clean doc
