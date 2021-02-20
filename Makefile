package?=bgrep

all: bgrep


DESTDIR?=/usr/local/opt/${package}
install_dir?=${DESTDIR}/usr

install: bgrep
	install -d ${install_dir}/bin
	install -s $< ${install_dir}/bin/

clean:
	rm -f ${package}
