#! /bin/bash

folder=/home/carlos/Documents/CS217B/ndnDrop

inotifywait -m -q -e delete -e create -e move  -r --format '%:e %w%f' $folder | while read file
  do
    echo "" > $folder/list.txt
    for f in $folder/*
      do
        echo $f >> $folder/list.txt
      done
  done
