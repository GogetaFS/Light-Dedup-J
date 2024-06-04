#!/bin/sh

if [ ! $1 ]; then
    timing=0
else
    timing=$1
fi

if [ ! $2 ]; then
    swap_time_threashold=1
else
    swap_time_threashold=$2
fi

if [ ! $3 ]; then
    dedup_mem_threashold=$((1024 * 1024))
else
    dedup_mem_threashold=$3
fi


make -j$(nproc)
echo umounting...
sudo umount /mnt/pmem
echo Removing the old kernel module...
sudo rmmod nova
echo Inserting the new kernel module...
sudo insmod nova.ko measure_timing=$timing swap_time_threashold=$swap_time_threashold dedup_mem_threashold=$dedup_mem_threashold

sleep 1

echo mounting...
sudo mount -t NOVA -o init -o data_cow /dev/pmem0 /mnt/pmem0
