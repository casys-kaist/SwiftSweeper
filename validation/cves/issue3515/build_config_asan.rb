MRuby::Build.new do |conf|
  toolchain :gcc
  enable_debug
  conf.gembox 'default'
  conf.cc.flags << '-fsanitize=address'
  conf.linker.flags << '-fsanitize=address'
  conf.cc.defines << %w(MRB_GC_STRESS)
end