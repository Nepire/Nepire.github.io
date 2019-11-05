#!/bin/bash
hexo clean
git add -A
git commit -m "source"
git push origin source
hexo g -d
