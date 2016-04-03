# standard libraries
import re

# 3rd party libraries

# project libraries

class CoreDict(dict):
  def __init__(self):
    self._exempt_from_find = []

  def find(self, **kwargs):
    """
    Find any keys where the values match the cumulative kwargs patterns

    If a keyword's value is a list, .find will match on any value for that keyword

    .find(id=1)
    >>> returns any item with a property 'id' and value in [1]
        possibilities:
           { 'id': 1, 'name': 'One'}
           { 'id': 1, 'name': 'Two'}
        
    .find(id=[1,2])
    >>> returns any item with a property 'id' and value in [1,2]
        possibilities:
           { 'id': 1, 'name': 'One'}
           { 'id': 2, 'name': 'One'}
           { 'id': 1, 'name': 'Two'}
           { 'id': 2, 'name': 'Two'}

    .find(id=1, name='One')
    >>> returns any item with a property 'id' and value in [1] AND a property 'name' and value in ['One']
        possibilities:
           { 'id': 1, 'name': 'One'}
        
    .find(id=[1,2], name='One')
    >>> returns any item with a property 'id' and value in [1,2] AND a property 'name' and value in ['One']
        possibilities:
           { 'id': 1, 'name': 'One'}
           { 'id': 2, 'name': 'One'}

    .find(id=[1,2], name=['One,Two'])
    >>> returns any item with a property 'id' and value in [1,2] AND a property 'name' and value in ['One','Two']
        possibilities:
           { 'id': 1, 'name': 'One'}
           { 'id': 2, 'name': 'One'}
           { 'id': 1, 'name': 'Two'}
           { 'id': 2, 'name': 'Two'}
    """
    results = []

    if kwargs:
      for item_id, item in self.items():
        item_matches = False
        for match_attr, match_attr_vals in kwargs.items():
          if not type(match_attr_vals) == type([]): match_attr_vals = [match_attr_vals]

          # does the current item have the property
          attr_to_check = None
          if match_attr in dir(item):
            attr_to_check = getattr(item, match_attr)
          elif 'has_key' in dir(item) and item.has_key(match_attr):
            attr_to_check = item[match_attr]

          if attr_to_check:
            # does the property match the specified values?
            for match_attr_val in match_attr_vals:
              if type(attr_to_check) in [type(''), type(u'')]:
                # string comparison
                match = re.search(r'{}'.format(match_attr_val), attr_to_check)
                if match:
                  item_matches = True
                  break # and move on to the new kwarg
                else:
                  item_matches = False
              else:
                # object comparison
                if attr_to_check == match_attr_val:
                  item_matches = True
                  break # and move on to the new kwarg
                else:
                  item_matches = False

        if item_matches: results.append(item_id)

    return results