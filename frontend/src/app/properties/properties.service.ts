import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { Property } from '../shared/interface/property';

@Injectable({
  providedIn: 'root'
})
export class PropertiesService {

  public readonly properties$: Observable<Property[]>;
  public readonly property$: Observable<Property>;
  private readonly propertiesSub = new BehaviorSubject<Property[]>([]);
  private readonly propertySub = new BehaviorSubject<Property>(null);

  constructor() {
    this.properties$ = this.propertiesSub.asObservable();
    this.property$ = this.propertySub.asObservable();
  }

  public get properties(): Property[] {
    return this.propertiesSub.getValue();
  }

  public set properties(property: Property[]) {
    this.propertiesSub.next(property);
  }


  public get property(): Property | null {
    return this.propertySub.getValue();
  }

  public set property(property: Property) {
    this.propertySub.next(property);
  }

  public addProperty(property: Property) {
    this.properties = [...this.properties, property];
  }

  public removeProperty(propId: string) {
    const properties = this.properties.filter(property => property.propId !== propId);
    this.properties = properties;
  }

  public updateProperty(updated: Property) {
    let findProperty = this.properties.find((property: Property) => property.propId === updated.propId);
    findProperty = { ...findProperty, ...updated };

    this.properties = this.properties.map(property => (property.propId === updated.propId) ?
      findProperty : property);
    this.property = findProperty;
  }
}