# libdivide and LibOTe

The library can be cloned and built with networking support as
```
git clone https://github.com/ridiculousfish/libdivide.git
cd libdivide
cmake .
make -j
sudo make install
```


```
git clone --recursive https://github.com/osu-crypto/libOTe.git
cd libOTe
mkdir -p out/build/linux
cmake -S . -B out/build/linux -DENABLE_ASAN=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo -DFETCH_AUTO=ON -DENABLE_RELIC=ON -DENABLE_ALL_OT=ON -DCOPROTO_ENABLE_BOOST=ON -DENABLE_SILENT_VOLE=ON -DENABLE_SSE=ON
cmake --build out/build/linux
sudo cmake --install out/build/linux
```
# How to call OKVS and OPRF
```
git clone https://github.com/savannahaa/BIR-BDC.git
cd BIR-BDC
mkdir build
cd build
cmake ..
make
./main
```

```
./main -paxos
./main -oprf
```
