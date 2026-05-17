#!/usr/bin/env ruby
# cleantex
# usage:
#  cleantex [texfile1 texfile2 ... texfileN]
#  where each file can be a directory (runs on every tex file in directory)
#  running "cleantex" with no arguments is equivalent to "cleantex ."
#  a single trailing dot or ".tex" is ignored (equivalent: a.tex a. a)

require 'set'

SUFFIXES = Set[*%w(.acn .acr .alg .aux .bbl .blg -blx.bib .dvi .fdb_latexmk .glg .glo .gls .idx .ilg .ind .ist .lof .log .lot .maf .mtc .mtc0 .nav .nlo .out .pdf .pdfsync .ps .snm .synctex.gz .synctex.gz(busy) .toc .vrb .xdy .xml .tdo)]

def clean_file(file)
  Dir.chdir(File.dirname file) do
    file = File.basename(file.gsub(/\.(tex)?$/, ''))
    texfile = file + '.tex'
    unless File.file? texfile
      puts "#{texfile}: not found"
      return
    end
    puts "#{file}:"

    count = 0
    Dir.glob("#{file}*") do |filename|
      next unless SUFFIXES.include? filename[file.length..-1]
      puts " #{filename}"
      File.delete filename
      count += 1
    end
    puts " #{count} #{count > 1 ? 'files' : 'file'} deleted" if count > 0
    puts " no files deleted" if count == 0
  end
end

def clean_all_files
  Dir.glob("*.tex", &method(:clean_file))
  if File.exist? "texput.log"
    puts "Deleting texput.log"
    File.delete "texput.log"
  end
end

ARGV.each do |arg|
  if File.directory? arg
    Dir.chdir(arg) { clean_all_files }
  else
    clean_file arg
  end
end
clean_all_files if ARGV.empty?
