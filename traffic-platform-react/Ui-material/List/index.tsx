/* eslint-disable*/
import React, {useEffect, useState} from 'react'
import styles from './index.module.scss'

export type IList = {}

export default function List(props: IList) {
  return <img src={require('./assets/image_1.png')} className={styles.image} />
}
