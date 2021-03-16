all: vatdata

vatdata:
	 go build -o vatdata *.go

install:
	 cp vatdata /usr/bin/
	 chmod +x /usr/bin/vatdata

run:
	 ./vatdata

debug:
	 clear
	 make clean
	 make
	 ./vatdata

uninstall:
	 rm -r /usr/bin/vatdata

clean:
	 -rm -r vatdata