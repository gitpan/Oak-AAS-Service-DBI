use ExtUtils::MakeMaker;

my $mm = new MM
 (
  {
   AUTHOR => "Daniel Ruoso <daniel\@ruoso.com>",
   ABSTRACT => "Perl Oak Component Tree",
   NAME => "Oak::AAS::Service::DBI",
   VERSION => "1.7",
   PREREQ_PM => 
   {
    'Oak::AAS::Service'   => '0',
    'Oak::IO::DBI' => '0',
    'Error' => '0.15',
    'Digest::MD5' => '0'
   }
  }
 );

$mm->flush;
