require "bundler/gem_tasks"
require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs << "tests"
  t.libs << "lib"
  t.test_files = FileList["tests/**/test_*.rb"]
end

task default: :test
